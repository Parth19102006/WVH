# WVH

Risk-adaptive authentication prototype using the existing WVH risk engine.

## Run

Use the bundled Python runtime from Codex, or any Python 3.12 environment with the existing dependencies available:

```powershell
& 'C:\Users\ASUS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' app.py
```

Then open http://127.0.0.1:8000.

Demo passwords accepted by the prototype are `password123` and `wvh-demo`. Medium-risk OTP verification uses the simulated code `246810`.
