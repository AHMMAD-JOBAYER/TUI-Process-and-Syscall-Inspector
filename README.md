# TUI Process and Syscall Inspector

A terminal-based user interface (TUI) application written in Rust for Linux that allows you to inspect running processes and monitor syscalls in real-time.

![Image](https://github.com/user-attachments/assets/5879bcba-a742-407f-b517-6216a813d099)

## Features

- **Process Selection:**  
  - Displays all running processes with details (PID, name, command).
  - Fuzzy filtering by typing to narrow down the list.
  - Use arrow keys to navigate and Enter to select a process.

- **Syscall Monitoring:**  
  - Attaches to the selected process using `strace` (requires appropriate privileges).
  - Displays only the unique syscalls called by the process.
  - Allows you to use fuzzy filtering on syscalls.

- **Process Control:**  
  - Kill the monitored process directly from the UI.
  - Return to the process selection screen at any time.

## Requirements

- **Linux** (This tool is designed for Linux environments)
- **Rust** (Latest stable version recommended)
- [`strace`](https://strace.io/) installed on your system
- Appropriate privileges (e.g., root access) to attach to processes with `strace`

## Installation

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/yourusername/TUI-Process-and-Syscall-Inspector.git
   cd TUI-Process-and-Syscall-Inspector
   ```

1. **Build the Project**
    Build the application in release mode:

   ```sh
    cargo build --release
   ```

## Usage
Run the application with:

```sh
cargo run --release
```
Or run the compiled binary directly:

```sh
./target/release/syscall-monitor
```
## Controls

### Process Selection Screen
- **Type:** Start typing to filter the list of processes.
- **Up/Down Arrow Keys:** Navigate through the process list.
- **Enter:** Select the highlighted process for monitoring.
- **q:** Quit the application.

### Syscall Monitoring Screen
- **f:** Toggle fuzzy search filtering for syscalls.
- **k:** Kill the monitored process (sends SIGKILL).
- **q or b:** Return to the process selection screen.

> **Note:** Monitoring syscalls via `strace` may require elevated privileges. If necessary, run the application using `sudo`:

```sh
sudo cargo run --release
```
or
```sh
sudo ./target/release/syscall-monitor
```

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

