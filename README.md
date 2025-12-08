# PTAgent

## Environment Setup

This project uses [uv](https://github.com/astral-sh/uv) for dependency management.

### Prerequisites

Ensure you have `uv` installed on your system.

### Installation

1. **Create a virtual environment:**

   ```bash
   uv venv
   ```

2. **Activate the virtual environment:**

   ```bash
   source .venv/bin/activate
   ```

3. **Install dependencies:**

   Since this project contains a `uv.lock` file, use `uv sync` to install dependencies exactly as specified in the lockfile:

   ```bash
   uv sync
   ```

   Alternatively, to install from `requirements.txt`:

   ```bash
   uv pip install -r requirements.txt
   ```