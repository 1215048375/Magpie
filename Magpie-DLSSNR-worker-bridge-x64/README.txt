Magpie DLSSNR cross-process bridge probe

1. Copy the SAME nvngx_dlssnr.dll that worked in NeuralScreen
   into this folder.
2. Run:
     powershell -ExecutionPolicy Bypass -File .\run-bridge-probe.ps1
3. Send BOTH console output and magpie-dlssnr-worker-bridge.log.

What this tests:
D3D11 shared input/output texture
    -> named NT handles
    -> nvngx.dll D3D12 worker
    -> Feature 18 Evaluate
    -> shared D3D11 fence
    -> D3D11 readback

It does not modify Magpie yet.
