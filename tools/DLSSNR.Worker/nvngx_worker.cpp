// DLSSNR external worker for Magpie.
//
// This file builds as an executable PE intentionally named "nvngx.dll".
// NeuralScreen and the local bridge probe both demonstrate that Feature 18
// succeeds on Ampere when NGX executes in a process with this image name.
//
// The Magpie process owns D3D11 input/output textures and a shared fence.
// This worker opens them by NT object name, owns all D3D12/NGX state, and
// evaluates Feature 18 repeatedly for the lifetime of the scaling session.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_defs.h>

#include "../../src/Magpie.Core/DLSSNRWorkerProtocol.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace Magpie::DLSSNRWorkerProtocol;

namespace {

constexpr unsigned long long DLSSNR_APPLICATION_ID = 0x0876232Cull;
constexpr NVSDK_NGX_Feature FEATURE_DLSSNR =
	static_cast<NVSDK_NGX_Feature>(18);

constexpr uint32_t NVAPI_ID_GPU_GET_ARCH_INFO = 0xD8265D24u;
constexpr uint32_t NVAPI_ARCH_AMPERE = 0x0170u;
constexpr uint32_t NVAPI_ARCH_BLACKWELL2 = 0x01B0u;
constexpr size_t NVAPI_ARCH_HOOK_SIZE = 12;

FILE* g_log = nullptr;

void Log(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (g_log) {
		vfprintf(g_log, fmt, args);
		fputc('\n', g_log);
		fflush(g_log);
	}
	va_end(args);

	va_start(args, fmt);
	vprintf(fmt, args);
	fputc('\n', stdout);
	fflush(stdout);
	va_end(args);
}

std::filesystem::path ExePath() {
	std::wstring buffer(32768, L'\0');
	const DWORD size = GetModuleFileNameW(
		nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
	if (!size || size >= buffer.size()) return {};
	buffer.resize(size);
	return std::filesystem::path(buffer);
}

struct NvGpuArchInfoCompat {
	uint32_t version;
	uint32_t architecture;
	uint32_t implementation;
	uint32_t revision;
};

using NvApiQueryInterfaceFn = void* (__cdecl*)(uint32_t);
using NvApiGpuGetArchInfoFn =
	int (__cdecl*)(void*, NvGpuArchInfoCompat*);

std::mutex g_archHookMutex;
NvApiGpuGetArchInfoFn g_realGpuGetArchInfo = nullptr;
std::array<uint8_t, NVAPI_ARCH_HOOK_SIZE> g_archOriginalBytes{};
bool g_archHookPatched = false;
std::atomic<bool> g_archLogged = false;

int __cdecl HookedGpuGetArchInfo(
	void* gpu,
	NvGpuArchInfoCompat* archInfo);

bool SetArchHook(bool enabled) {
	if (!g_realGpuGetArchInfo) return false;

	auto* target = reinterpret_cast<uint8_t*>(
		reinterpret_cast<uintptr_t>(g_realGpuGetArchInfo));

	DWORD oldProtection = 0;
	if (!VirtualProtect(
			target, NVAPI_ARCH_HOOK_SIZE,
			PAGE_EXECUTE_READWRITE, &oldProtection)) {
		return false;
	}

	if (enabled) {
		std::array<uint8_t, NVAPI_ARCH_HOOK_SIZE> patch{
			0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0
		};
		const uint64_t hookAddress =
			reinterpret_cast<uint64_t>(&HookedGpuGetArchInfo);
		std::memcpy(patch.data() + 2, &hookAddress, sizeof(hookAddress));
		std::memcpy(target, patch.data(), patch.size());
		g_archHookPatched = true;
	} else {
		std::memcpy(
			target, g_archOriginalBytes.data(),
			g_archOriginalBytes.size());
		g_archHookPatched = false;
	}

	FlushInstructionCache(
		GetCurrentProcess(), target, NVAPI_ARCH_HOOK_SIZE);

	DWORD ignored = 0;
	VirtualProtect(
		target, NVAPI_ARCH_HOOK_SIZE,
		oldProtection, &ignored);
	return true;
}

int __cdecl HookedGpuGetArchInfo(
	void* gpu,
	NvGpuArchInfoCompat* archInfo
) {
	std::lock_guard lock(g_archHookMutex);

	if (!SetArchHook(false)) return -1;
	const int result =
		g_realGpuGetArchInfo ? g_realGpuGetArchInfo(gpu, archInfo) : -1;
	SetArchHook(true);

	if (result == 0 && archInfo) {
		const uint32_t realArchitecture = archInfo->architecture;
		if (realArchitecture == NVAPI_ARCH_AMPERE) {
			archInfo->architecture = NVAPI_ARCH_BLACKWELL2;
			if (!g_archLogged.exchange(true)) {
				Log("ARCH: real=0x%03x spoofed=0x%03x",
					realArchitecture, archInfo->architecture);
			}
		} else if (!g_archLogged.exchange(true)) {
			Log("ARCH: observed=0x%03x (not rewritten)",
				realArchitecture);
		}
	}

	return result;
}

class ScopedArchSpoof {
public:
	bool Install() {
		_module = LoadLibraryW(L"nvapi64.dll");
		if (!_module) {
			Log("ARCH: LoadLibrary(nvapi64.dll) failed: %lu",
				GetLastError());
			return false;
		}

		const auto query = reinterpret_cast<NvApiQueryInterfaceFn>(
			GetProcAddress(_module, "nvapi_QueryInterface"));
		if (!query) {
			Log("ARCH: nvapi_QueryInterface not found");
			return false;
		}

		g_realGpuGetArchInfo =
			reinterpret_cast<NvApiGpuGetArchInfoFn>(
				query(NVAPI_ID_GPU_GET_ARCH_INFO));
		if (!g_realGpuGetArchInfo) {
			Log("ARCH: NvAPI_GPU_GetArchInfo query failed");
			return false;
		}

		std::memcpy(
			g_archOriginalBytes.data(),
			reinterpret_cast<void*>(
				reinterpret_cast<uintptr_t>(g_realGpuGetArchInfo)),
			g_archOriginalBytes.size());

		if (!SetArchHook(true)) {
			Log("ARCH: failed to patch NvAPI_GPU_GetArchInfo");
			return false;
		}

		_installed = true;
		Log("ARCH: hook installed");
		return true;
	}

	~ScopedArchSpoof() {
		if (_installed && g_realGpuGetArchInfo && g_archHookPatched) {
			std::lock_guard lock(g_archHookMutex);
			SetArchHook(false);
			Log("ARCH: hook removed");
		}
		g_realGpuGetArchInfo = nullptr;
		if (_module) FreeLibrary(_module);
	}

private:
	HMODULE _module = nullptr;
	bool _installed = false;
};

ComPtr<IDXGIAdapter1> PickNvidiaAdapter() {
	ComPtr<IDXGIFactory6> factory;
	if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) {
		return {};
	}

	for (UINT i = 0;; ++i) {
		ComPtr<IDXGIAdapter1> adapter;
		const HRESULT hr = factory->EnumAdapterByGpuPreference(
			i,
			DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
			IID_PPV_ARGS(&adapter));
		if (hr == DXGI_ERROR_NOT_FOUND) break;
		if (FAILED(hr)) continue;

		DXGI_ADAPTER_DESC1 desc{};
		if (FAILED(adapter->GetDesc1(&desc))) continue;
		if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) continue;

		if (desc.VendorId == 0x10DE) {
			char name[256]{};
			WideCharToMultiByte(
				CP_UTF8, 0, desc.Description, -1,
				name, static_cast<int>(sizeof(name)),
				nullptr, nullptr);
			Log("DXGI: selected %s vendor=0x%04x device=0x%04x",
				name, desc.VendorId, desc.DeviceId);
			return adapter;
		}
	}

	return {};
}

template <typename T>
T Export(HMODULE module, const char* name) {
	return reinterpret_cast<T>(
		GetProcAddress(module, name));
}

using SnippetInitExtFn = NVSDK_NGX_Result(NVSDK_CONV*)(
	unsigned long long, const wchar_t*, ID3D12Device*,
	NVSDK_NGX_Version, const NVSDK_NGX_Parameter*);
using SnippetCreateFeatureFn = NVSDK_NGX_Result(NVSDK_CONV*)(
	ID3D12GraphicsCommandList*, NVSDK_NGX_Feature,
	NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
using SnippetEvaluateFeatureFn = NVSDK_NGX_Result(NVSDK_CONV*)(
	ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*,
	const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
using SnippetReleaseFeatureFn =
	NVSDK_NGX_Result(NVSDK_CONV*)(NVSDK_NGX_Handle*);
using SnippetShutdownFn =
	NVSDK_NGX_Result(NVSDK_CONV*)(ID3D12Device*);

NVSDK_NGX_Result NVSDK_CONV ScalingRatioCallback(
	NVSDK_NGX_Parameter* parameters
) {
	if (!parameters) {
		return NVSDK_NGX_Result_FAIL_InvalidParameter;
	}
	parameters->Set("DLSSNR.ScalingRatio", 1.0f);
	return NVSDK_NGX_Result_Success;
}

void SetSubrect(
	NVSDK_NGX_Parameter* parameters,
	const char* prefix,
	uint32_t width,
	uint32_t height
) {
	const std::string baseX =
		std::string(prefix) + "SubrectBaseX";
	const std::string baseY =
		std::string(prefix) + "SubrectBaseY";
	const std::string rectWidth =
		std::string(prefix) + "SubrectWidth";
	const std::string rectHeight =
		std::string(prefix) + "SubrectHeight";

	parameters->Set(baseX.c_str(), 0u);
	parameters->Set(baseY.c_str(), 0u);
	parameters->Set(rectWidth.c_str(), width);
	parameters->Set(rectHeight.c_str(), height);
}

void SetCreateParameters(
	NVSDK_NGX_Parameter* parameters,
	uint32_t width,
	uint32_t height
) {
	parameters->Set("DLSSNR.Width", width);
	parameters->Set("DLSSNR.Height", height);
	parameters->Set("DLSSNR.InputWidth", width);
	parameters->Set("DLSSNR.InputHeight", height);
	parameters->Set("DLSSNR.OutputWidth", width);
	parameters->Set("DLSSNR.OutputHeight", height);
	parameters->Set("DLSSNR.Output.Width", width);
	parameters->Set("DLSSNR.Output.Height", height);
	parameters->Set("DLSSNR.Upscaling", 0u);
	parameters->Set("DLSSNR.Scale", 1.0f);
	parameters->Set("DLSSNR.ScalingRatio", 1.0f);
	parameters->Set(
		"DLSSNRComputeScalingRatioCallback",
		reinterpret_cast<void*>(
			reinterpret_cast<uintptr_t>(&ScalingRatioCallback)));
	parameters->Set("DLSSNR.Hint.Render.Preset", 0);

	parameters->Set(NVSDK_NGX_Parameter_Width, width);
	parameters->Set(NVSDK_NGX_Parameter_Height, height);
	parameters->Set(
		NVSDK_NGX_Parameter_PerfQualityValue,
		static_cast<int>(
			NVSDK_NGX_PerfQuality_Value_Balanced));
	parameters->Set(
		NVSDK_NGX_Parameter_CreationNodeMask, 1u);
	parameters->Set(
		NVSDK_NGX_Parameter_VisibilityNodeMask, 1u);
}

struct EvaluateSettings {
	int32_t style = 0;
	float intensity = 1.0f;
	float localToneStrength = 1.0f;
	float localStructureStrength = 1.0f;
	float skinStructureStrength = 0.0f;
	bool useAutoMask = false;
	bool uiCorrection = false;
	bool resetHistory = false;
};

EvaluateSettings ReadSettings(ControlBlock* control) {
	EvaluateSettings result;
	if (!control) return result;

	MemoryBarrier();
	result.style = control->style;
	result.intensity = control->intensity;
	result.localToneStrength = control->localToneStrength;
	result.localStructureStrength =
		control->localStructureStrength;
	result.skinStructureStrength =
		control->skinStructureStrength;
	result.useAutoMask = control->useAutoMask != 0;
	result.uiCorrection = control->uiCorrection != 0;
	result.resetHistory =
		InterlockedExchange(&control->resetHistory, 0) != 0;
	MemoryBarrier();
	return result;
}

void SetEvaluateParameters(
	NVSDK_NGX_Parameter* parameters,
	ID3D12Resource* color,
	ID3D12Resource* output,
	ID3D12Resource* motion,
	ID3D12Resource* depth,
	uint32_t width,
	uint32_t height,
	const EvaluateSettings& settings
) {
	parameters->Set("DLSSNR.Color", color);
	parameters->Set("DLSSNR.Output", output);
	parameters->Set("DLSSNR.MVec", motion);
	parameters->Set("DLSSNR.Depth", depth);

	SetSubrect(parameters, "DLSSNR.Color", width, height);
	SetSubrect(parameters, "DLSSNR.Output", width, height);
	SetSubrect(parameters, "DLSSNR.MVec", width, height);
	SetSubrect(parameters, "DLSSNR.Depth", width, height);

	parameters->Set("DLSSNR.MVecScaleX", 1.0f);
	parameters->Set("DLSSNR.MVecScaleY", 1.0f);
	parameters->Set("DLSSNR.DepthInverted", 1);
	parameters->Set("DLSS.Indicator.Invert.X.Axis", 0);
	parameters->Set("DLSS.Indicator.Invert.Y.Axis", 0);
	parameters->Set("DLSSNR.Enabled", 1);
	parameters->Set("DLSSNR.Reset",
		settings.resetHistory ? 1 : 0);

	parameters->Set("DLSSNR.Style", settings.style);
	parameters->Set("DLSSNR.Intensity", settings.intensity);
	parameters->Set(
		"DLSSNR.LocalToneStrength",
		settings.localToneStrength);
	parameters->Set(
		"DLSSNR.LocalStructureStrength",
		settings.localStructureStrength);
	parameters->Set(
		"DLSSNR.SkinStructureStrength",
		settings.skinStructureStrength);
	parameters->Set(
		"DLSSNR.UseAutoMask",
		settings.useAutoMask ? 1 : 0);
	parameters->Set(
		"DLSSNR.UICorrection",
		settings.uiCorrection ? 1 : 0);
}

ComPtr<ID3D12Resource> CreateAuxTexture(
	ID3D12Device* device,
	DXGI_FORMAT format,
	uint32_t width,
	uint32_t height
) {
	D3D12_HEAP_PROPERTIES heap{};
	heap.Type = D3D12_HEAP_TYPE_DEFAULT;

	D3D12_RESOURCE_DESC desc{};
	desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
	desc.Width = width;
	desc.Height = height;
	desc.DepthOrArraySize = 1;
	desc.MipLevels = 1;
	desc.Format = format;
	desc.SampleDesc.Count = 1;
	desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
	desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;

	ComPtr<ID3D12Resource> result;
	if (FAILED(device->CreateCommittedResource(
		&heap,
		D3D12_HEAP_FLAG_NONE,
		&desc,
		D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
		nullptr,
		IID_PPV_ARGS(&result)))) {
		return {};
	}

	return result;
}

template <typename T>
ComPtr<T> OpenNamedSharedObject(
	ID3D12Device* device,
	const std::wstring& name
) {
	HANDLE handle = nullptr;
	const HRESULT nameResult =
		device->OpenSharedHandleByName(
			name.c_str(), GENERIC_ALL, &handle);
	if (FAILED(nameResult) || !handle) {
		Log("SHARE: OpenSharedHandleByName(%ls) failed hr=0x%08x",
			name.c_str(),
			static_cast<unsigned>(nameResult));
		return {};
	}

	ComPtr<T> object;
	const HRESULT openResult =
		device->OpenSharedHandle(
			handle, IID_PPV_ARGS(&object));
	CloseHandle(handle);

	if (FAILED(openResult)) {
		Log("SHARE: OpenSharedHandle(%ls) failed hr=0x%08x",
			name.c_str(),
			static_cast<unsigned>(openResult));
		return {};
	}

	return object;
}

bool WaitQueueIdle(
	ID3D12Device* device,
	ID3D12CommandQueue* queue
) {
	ComPtr<ID3D12Fence> fence;
	if (FAILED(device->CreateFence(
		0, D3D12_FENCE_FLAG_NONE,
		IID_PPV_ARGS(&fence)))) {
		return false;
	}

	HANDLE eventHandle =
		CreateEventW(nullptr, FALSE, FALSE, nullptr);
	if (!eventHandle) return false;

	bool ok = false;
	if (SUCCEEDED(queue->Signal(fence.Get(), 1)) &&
		SUCCEEDED(fence->SetEventOnCompletion(1, eventHandle))) {
		ok = WaitForSingleObject(
			eventHandle, 10000) == WAIT_OBJECT_0;
	}

	CloseHandle(eventHandle);
	return ok;
}

int RunWorker(const std::wstring& session) {
	const auto exePath = ExePath();
	if (exePath.empty()) return 2;

	std::wstring processName =
		exePath.filename().wstring();
	for (wchar_t& ch : processName) {
		ch = static_cast<wchar_t>(towlower(ch));
	}
	if (processName.find(L"nvngx.dll") ==
		std::wstring::npos) {
		Log("FATAL: worker image name must contain nvngx.dll");
		return 3;
	}

	const auto directory = exePath.parent_path();
	const auto snippetPath =
		directory / L"nvngx_dlssnr.dll";
	if (!std::filesystem::exists(snippetPath)) {
		Log("FATAL: missing %ls", snippetPath.c_str());
		return 4;
	}

	HANDLE controlMapping = OpenFileMappingW(
		FILE_MAP_ALL_ACCESS, FALSE,
		ControlName(session).c_str());
	if (!controlMapping) {
		Log("CONTROL: OpenFileMapping failed win32=%lu",
			GetLastError());
		return 5;
	}
	auto* control = static_cast<ControlBlock*>(
		MapViewOfFile(
			controlMapping,
			FILE_MAP_ALL_ACCESS,
			0, 0, sizeof(ControlBlock)));
	if (!control) {
		Log("CONTROL: MapViewOfFile failed win32=%lu",
			GetLastError());
		CloseHandle(controlMapping);
		return 6;
	}

	auto cleanupControl = [&]() {
		UnmapViewOfFile(control);
		CloseHandle(controlMapping);
	};

	if (control->magic != MAGIC ||
		control->version != VERSION ||
		!control->width || !control->height) {
		Log("CONTROL: incompatible block");
		cleanupControl();
		return 7;
	}

	HANDLE readyEvent = OpenEventW(
		EVENT_MODIFY_STATE | SYNCHRONIZE,
		FALSE, ReadyName(session).c_str());
	HANDLE stopEvent = OpenEventW(
		SYNCHRONIZE,
		FALSE, StopName(session).c_str());
	if (!readyEvent || !stopEvent) {
		Log("CONTROL: open ready/stop event failed win32=%lu",
			GetLastError());
		if (readyEvent) CloseHandle(readyEvent);
		if (stopEvent) CloseHandle(stopEvent);
		cleanupControl();
		return 8;
	}

	auto fail = [&](LONG result, int exitCode) {
		InterlockedExchange(
			&control->lastResult, result);
		InterlockedExchange(
			&control->workerState,
			static_cast<LONG>(WorkerState::Failed));
		SetEvent(readyEvent);
		CloseHandle(readyEvent);
		CloseHandle(stopEvent);
		cleanupControl();
		return exitCode;
	};

	ScopedArchSpoof archSpoof;
	if (!archSpoof.Install()) {
		return fail(
			static_cast<LONG>(
				NVSDK_NGX_Result_FAIL_FeatureNotSupported),
			9);
	}

	auto adapter = PickNvidiaAdapter();
	if (!adapter) {
		return fail(E_FAIL, 10);
	}

	ComPtr<ID3D12Device> device;
	HRESULT hr = D3D12CreateDevice(
		adapter.Get(),
		D3D_FEATURE_LEVEL_11_0,
		IID_PPV_ARGS(&device));
	if (FAILED(hr)) {
		Log("D3D12: CreateDevice failed hr=0x%08x",
			static_cast<unsigned>(hr));
		return fail(hr, 11);
	}

	auto input =
		OpenNamedSharedObject<ID3D12Resource>(
			device.Get(), InputName(session));
	auto output =
		OpenNamedSharedObject<ID3D12Resource>(
			device.Get(), OutputName(session));
	auto sharedFence =
		OpenNamedSharedObject<ID3D12Fence>(
			device.Get(), FenceName(session));
	if (!input || !output || !sharedFence) {
		return fail(E_HANDLE, 12);
	}

	D3D12_COMMAND_QUEUE_DESC queueDesc{};
	queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;

	ComPtr<ID3D12CommandQueue> queue;
	ComPtr<ID3D12CommandAllocator> allocator;
	ComPtr<ID3D12GraphicsCommandList> commandList;

	hr = device->CreateCommandQueue(
		&queueDesc, IID_PPV_ARGS(&queue));
	if (SUCCEEDED(hr)) {
		hr = device->CreateCommandAllocator(
			D3D12_COMMAND_LIST_TYPE_DIRECT,
			IID_PPV_ARGS(&allocator));
	}
	if (SUCCEEDED(hr)) {
		hr = device->CreateCommandList(
			0,
			D3D12_COMMAND_LIST_TYPE_DIRECT,
			allocator.Get(), nullptr,
			IID_PPV_ARGS(&commandList));
	}
	if (FAILED(hr)) {
		Log("D3D12: command objects failed hr=0x%08x",
			static_cast<unsigned>(hr));
		return fail(hr, 13);
	}

	NVSDK_NGX_Result ngxResult =
		NVSDK_NGX_D3D12_Init(
			DLSSNR_APPLICATION_ID,
			directory.c_str(),
			device.Get());
	Log("NGX CORE: Init -> 0x%08x",
		static_cast<unsigned>(ngxResult));
	if (ngxResult != NVSDK_NGX_Result_Success) {
		return fail(
			static_cast<LONG>(ngxResult), 14);
	}

	NVSDK_NGX_Parameter* parameters = nullptr;
	ngxResult =
		NVSDK_NGX_D3D12_GetCapabilityParameters(
			&parameters);
	Log("NGX CORE: GetCapabilityParameters -> 0x%08x params=%p",
		static_cast<unsigned>(ngxResult),
		static_cast<void*>(parameters));
	if (ngxResult != NVSDK_NGX_Result_Success ||
		!parameters) {
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(
			static_cast<LONG>(ngxResult), 15);
	}

	HMODULE snippet = LoadLibraryExW(
		snippetPath.c_str(), nullptr,
		LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
		LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
	if (!snippet) {
		Log("SNIPPET: LoadLibrary failed win32=%lu",
			GetLastError());
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(E_FAIL, 16);
	}

	const auto initExt =
		Export<SnippetInitExtFn>(
			snippet, "NVSDK_NGX_D3D12_Init_Ext");
	const auto createFeature =
		Export<SnippetCreateFeatureFn>(
			snippet, "NVSDK_NGX_D3D12_CreateFeature");
	const auto evaluateFeature =
		Export<SnippetEvaluateFeatureFn>(
			snippet, "NVSDK_NGX_D3D12_EvaluateFeature");
	const auto releaseFeature =
		Export<SnippetReleaseFeatureFn>(
			snippet, "NVSDK_NGX_D3D12_ReleaseFeature");
	const auto snippetShutdown =
		Export<SnippetShutdownFn>(
			snippet, "NVSDK_NGX_D3D12_Shutdown1");

	if (!initExt || !createFeature ||
		!evaluateFeature || !releaseFeature ||
		!snippetShutdown) {
		Log("SNIPPET: required exports incomplete");
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(E_NOINTERFACE, 17);
	}

	ngxResult = initExt(
		DLSSNR_APPLICATION_ID,
		directory.c_str(),
		device.Get(),
		NVSDK_NGX_Version_API,
		parameters);
	Log("SNIPPET: Init_Ext -> 0x%08x",
		static_cast<unsigned>(ngxResult));
	if (ngxResult != NVSDK_NGX_Result_Success) {
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(
			static_cast<LONG>(ngxResult), 18);
	}

	const uint32_t width = control->width;
	const uint32_t height = control->height;
	SetCreateParameters(parameters, width, height);

	NVSDK_NGX_Handle* feature = nullptr;
	ngxResult = createFeature(
		commandList.Get(),
		FEATURE_DLSSNR,
		parameters,
		&feature);
	Log("SNIPPET: CreateFeature(18) -> 0x%08x handle=%p",
		static_cast<unsigned>(ngxResult),
		static_cast<void*>(feature));
	if (ngxResult != NVSDK_NGX_Result_Success ||
		!feature) {
		snippetShutdown(device.Get());
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(
			static_cast<LONG>(ngxResult), 19);
	}

	hr = commandList->Close();
	if (FAILED(hr)) {
		releaseFeature(feature);
		snippetShutdown(device.Get());
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(hr, 20);
	}
	{
		ID3D12CommandList* lists[]{ commandList.Get() };
		queue->ExecuteCommandLists(1, lists);
	}
	if (!WaitQueueIdle(device.Get(), queue.Get())) {
		releaseFeature(feature);
		snippetShutdown(device.Get());
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(E_FAIL, 21);
	}

	auto motion = CreateAuxTexture(
		device.Get(),
		DXGI_FORMAT_R16G16_FLOAT,
		width, height);
	auto depth = CreateAuxTexture(
		device.Get(),
		DXGI_FORMAT_R32_FLOAT,
		width, height);
	if (!motion || !depth) {
		releaseFeature(feature);
		snippetShutdown(device.Get());
		FreeLibrary(snippet);
		NVSDK_NGX_D3D12_DestroyParameters(parameters);
		NVSDK_NGX_D3D12_Shutdown1(device.Get());
		return fail(E_OUTOFMEMORY, 22);
	}

	D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
	heapDesc.Type =
		D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
	heapDesc.NumDescriptors = 2;
	heapDesc.Flags =
		D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

	ComPtr<ID3D12DescriptorHeap> descriptorHeap;
	hr = device->CreateDescriptorHeap(
		&heapDesc,
		IID_PPV_ARGS(&descriptorHeap));
	if (FAILED(hr)) {
		return fail(hr, 23);
	}

	const UINT descriptorStride =
		device->GetDescriptorHandleIncrementSize(
			D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
	auto motionCpu =
		descriptorHeap->GetCPUDescriptorHandleForHeapStart();
	auto motionGpu =
		descriptorHeap->GetGPUDescriptorHandleForHeapStart();
	auto depthCpu = motionCpu;
	auto depthGpu = motionGpu;
	depthCpu.ptr += descriptorStride;
	depthGpu.ptr += descriptorStride;

	D3D12_UNORDERED_ACCESS_VIEW_DESC motionUav{};
	motionUav.Format = DXGI_FORMAT_R16G16_FLOAT;
	motionUav.ViewDimension =
		D3D12_UAV_DIMENSION_TEXTURE2D;
	device->CreateUnorderedAccessView(
		motion.Get(), nullptr,
		&motionUav, motionCpu);

	D3D12_UNORDERED_ACCESS_VIEW_DESC depthUav{};
	depthUav.Format = DXGI_FORMAT_R32_FLOAT;
	depthUav.ViewDimension =
		D3D12_UAV_DIMENSION_TEXTURE2D;
	device->CreateUnorderedAccessView(
		depth.Get(), nullptr,
		&depthUav, depthCpu);

	hr = allocator->Reset();
	if (SUCCEEDED(hr)) {
		hr = commandList->Reset(
			allocator.Get(), nullptr);
	}
	if (FAILED(hr)) return fail(hr, 24);

	ID3D12DescriptorHeap* heaps[]{ descriptorHeap.Get() };
	commandList->SetDescriptorHeaps(1, heaps);
	const float zero[4]{ 0, 0, 0, 0 };
	commandList->ClearUnorderedAccessViewFloat(
		motionGpu, motionCpu,
		motion.Get(), zero, 0, nullptr);
	commandList->ClearUnorderedAccessViewFloat(
		depthGpu, depthCpu,
		depth.Get(), zero, 0, nullptr);

	std::array<D3D12_RESOURCE_BARRIER, 2>
		guidanceBarriers{};
	for (size_t i = 0; i < guidanceBarriers.size(); ++i) {
		guidanceBarriers[i].Type =
			D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
		guidanceBarriers[i].Transition.Subresource =
			D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
		guidanceBarriers[i].Transition.StateBefore =
			D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
		guidanceBarriers[i].Transition.StateAfter =
			D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE;
	}
	guidanceBarriers[0].Transition.pResource =
		motion.Get();
	guidanceBarriers[1].Transition.pResource =
		depth.Get();
	commandList->ResourceBarrier(
		static_cast<UINT>(guidanceBarriers.size()),
		guidanceBarriers.data());

	hr = commandList->Close();
	if (FAILED(hr)) return fail(hr, 25);
	{
		ID3D12CommandList* lists[]{ commandList.Get() };
		queue->ExecuteCommandLists(1, lists);
	}
	if (!WaitQueueIdle(device.Get(), queue.Get())) {
		return fail(E_FAIL, 26);
	}

	HANDLE fenceEvent =
		CreateEventW(nullptr, FALSE, FALSE, nullptr);
	if (!fenceEvent) return fail(E_FAIL, 27);

	InterlockedExchange(
		&control->workerState,
		static_cast<LONG>(WorkerState::Ready));
	InterlockedExchange(
		&control->lastResult,
		static_cast<LONG>(NVSDK_NGX_Result_Success));
	SetEvent(readyEvent);
	Log("READY: Feature 18 initialized for %ux%u",
		width, height);

	uint64_t inputReady = 1;
	uint64_t evaluateCount = 0;

	for (;;) {
		if (WaitForSingleObject(
			stopEvent, 0) == WAIT_OBJECT_0) {
			break;
		}

		if (sharedFence->GetCompletedValue() < inputReady) {
			ResetEvent(fenceEvent);
			hr = sharedFence->SetEventOnCompletion(
				inputReady, fenceEvent);
			if (FAILED(hr)) {
				Log("FENCE: SetEventOnCompletion failed hr=0x%08x",
					static_cast<unsigned>(hr));
				InterlockedExchange(
					&control->lastResult, hr);
				break;
			}

			HANDLE waits[]{ fenceEvent, stopEvent };
			const DWORD wait = WaitForMultipleObjects(
				2, waits, FALSE, 100);
			if (wait == WAIT_OBJECT_0 + 1) break;
			if (wait != WAIT_OBJECT_0 &&
				wait != WAIT_TIMEOUT) {
				InterlockedExchange(
					&control->lastResult, E_FAIL);
				break;
			}
			if (wait == WAIT_TIMEOUT) continue;
		}

		hr = allocator->Reset();
		if (SUCCEEDED(hr)) {
			hr = commandList->Reset(
				allocator.Get(), nullptr);
		}
		if (FAILED(hr)) {
			InterlockedExchange(
				&control->lastResult, hr);
			break;
		}

		D3D12_RESOURCE_BARRIER barriers[2]{};
		barriers[0].Type =
			D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
		barriers[0].Transition = {
			input.Get(),
			D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
			D3D12_RESOURCE_STATE_COMMON,
			D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE
		};
		barriers[1].Type =
			D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
		barriers[1].Transition = {
			output.Get(),
			D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
			D3D12_RESOURCE_STATE_COMMON,
			D3D12_RESOURCE_STATE_UNORDERED_ACCESS
		};
		commandList->ResourceBarrier(
			ARRAYSIZE(barriers), barriers);

		const EvaluateSettings settings =
			ReadSettings(control);
		SetEvaluateParameters(
			parameters,
			input.Get(), output.Get(),
			motion.Get(), depth.Get(),
			width, height, settings);

		ngxResult = evaluateFeature(
			commandList.Get(),
			feature,
			parameters,
			nullptr);
		InterlockedExchange(
			&control->lastResult,
			static_cast<LONG>(ngxResult));

		for (D3D12_RESOURCE_BARRIER& barrier : barriers) {
			std::swap(
				barrier.Transition.StateBefore,
				barrier.Transition.StateAfter);
		}
		commandList->ResourceBarrier(
			ARRAYSIZE(barriers), barriers);

		hr = commandList->Close();
		if (FAILED(hr)) {
			InterlockedExchange(
				&control->lastResult, hr);
			break;
		}

		{
			ID3D12CommandList* lists[]{
				commandList.Get()
			};
			queue->ExecuteCommandLists(1, lists);
		}

		const uint64_t outputReady = inputReady + 1;
		hr = queue->Signal(
			sharedFence.Get(), outputReady);
		if (FAILED(hr)) {
			InterlockedExchange(
				&control->lastResult, hr);
			break;
		}

		InterlockedExchange64(
			&control->lastCompletedFence,
			static_cast<LONG64>(outputReady));
		InterlockedExchange(
			&control->workerState,
			static_cast<LONG>(WorkerState::Running));

		++evaluateCount;
		if (evaluateCount == 1 ||
			evaluateCount % 120 == 0 ||
			ngxResult != NVSDK_NGX_Result_Success) {
			Log("EVALUATE: count=%llu inputFence=%llu outputFence=%llu result=0x%08x",
				static_cast<unsigned long long>(evaluateCount),
				static_cast<unsigned long long>(inputReady),
				static_cast<unsigned long long>(outputReady),
				static_cast<unsigned>(ngxResult));
		}

		if (ngxResult != NVSDK_NGX_Result_Success) {
			break;
		}

		inputReady += 2;
	}

	InterlockedExchange(
		&control->workerState,
		static_cast<LONG>(WorkerState::Stopping));

	WaitQueueIdle(device.Get(), queue.Get());
	releaseFeature(feature);
	snippetShutdown(device.Get());
	FreeLibrary(snippet);
	NVSDK_NGX_D3D12_DestroyParameters(parameters);
	NVSDK_NGX_D3D12_Shutdown1(device.Get());

	CloseHandle(fenceEvent);
	CloseHandle(readyEvent);
	CloseHandle(stopEvent);
	cleanupControl();

	Log("STOP: worker exited cleanly");
	return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	const auto exePath = ExePath();
	const auto logPath =
		(exePath.empty()
			? std::filesystem::path(L".")
			: exePath.parent_path()) /
		L"magpie-dlssnr-worker.log";
	_wfopen_s(&g_log, logPath.c_str(), L"ab");

	Log("=== Magpie DLSSNR external worker ===");
	Log("PROCESS: %ls", exePath.c_str());

	int result = 64;
	if (argc == 3 &&
		std::wstring_view(argv[1]) == L"--magpie-session") {
		result = RunWorker(argv[2]);
	} else {
		Log("USAGE: nvngx.dll --magpie-session <session>");
	}

	Log("EXIT: %d", result);
	if (g_log) {
		fclose(g_log);
		g_log = nullptr;
	}
	return result;
}
