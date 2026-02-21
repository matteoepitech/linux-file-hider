# Linux File Hider

Linux kernel module that hooks `getdents64` (via `ftrace`) to hide a specific file name from directory listings.

By default, it hides entries named `HIDDEN_FILE`.

## Main Commands

### 1) Build the module
```bash
make
```

### 2) Load the module into the kernel
```bash
make load
```

### 3) Unload the module from the kernel
```bash
make unload
```

## Optional

Clean build files:
```bash
make clean
```

This project is for educational purposes.
