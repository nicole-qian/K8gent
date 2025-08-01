# Kubernetes & Bare-Metal Server Management Agent

This project implements a sophisticated AI agent using the LangChain framework to automate the management of bare-metal servers and Kubernetes clusters. The agent is equipped with a comprehensive suite of tools that allow it to interact with Dell iDRAC for hardware management via the Redfish API and with remote servers via SSH. It can perform tasks ranging from checking server status and configuring RAID to deploying an operating system and setting up a Kubernetes cluster.

## ✨ Features

* **Server Hardware Management (iDRAC/Redfish):**
    * Get server power status, health, and basic inventory.
    * Perform power control actions (On, Off, Restart).
    * Read and modify BIOS settings.
    * Mount and eject virtual media (ISOs) for OS installation.
    * Set one-time boot devices.
    * Discover and create complex RAID configurations.
    * Monitor asynchronous jobs (e.g., RAID creation, BIOS updates).
* **Remote Server Management (SSH/SFTP):**
    * Execute arbitrary commands and scripts on remote hosts.
    * Upload and download files.
    * Read content from remote files.
* **Network Utilities:**
    * Check network connectivity to a specific host and port.
    * Read configuration files or instructions from a web server.
* **Conversational AI:**
    * Powered by a large language model to understand complex, natural language commands.
    * Maintains conversation history for contextual understanding.
    * Uses a ReAct (Reasoning and Acting) framework to intelligently select and chain tools to accomplish goals.

## 🚀 Getting Started

### Prerequisites

* Python 3.8+
* Access to a Dell server with iDRAC enabled and network-accessible.
* An NGINX or other web server to host instruction files (for complex, multi-step tasks).
* API keys for LangChain/LangSmith and Tavily Search.

### Installation

1.  **Clone the repository or save the script:**
    Save the code as `k8s_agent.py`.

2.  **Install required Python libraries:**
    ```bash
    pip install langchain langchain_core langchain_openai langchain_tavily langgraph redfish paramiko requests
    ```

3.  **Configure Environment Variables:**
    The script requires several environment variables to be set for API keys and endpoints.
    ```bash
    export LANGCHAIN_TRACING_V2="true"
    export LANGCHAIN_API_KEY="your_langsmith_api_key"
    export LANGCHAIN_ENDPOINT="[https://api.smith.langchain.com](https://api.smith.langchain.com)"
    export LANGCHAIN_PROJECT="My K8s Agent"
    export GOOGLE_API_KEY="your_google_api_key" # Or other model provider
    export TAVILY_API_KEY="your_tavily_api_key"
    export THIRD_PARTY_API_BASE="http://your_llm_provider_endpoint/v1"
    ```
    *Note: The script has some hardcoded keys and endpoints. It is highly recommended to replace these with environment variables for security.*

### Running the Agent

Execute the script from your terminal:
```bash
python k8s_agent.py
```
The agent will start, and you can begin interacting with it at the `You:` prompt.

## Usage

You can interact with the agent using natural language. Provide it with the necessary credentials (like iDRAC IP, username, and password) as part of your prompt.

### Example Interaction
```
You: Can you please check the server status for the iDRAC at 192.168.1.120 with username 'root' and password 'calvin'?
```

### Automated OS Installation & Kubernetes Deployment

The agent is capable of following a set of instructions from a text file hosted on a web server to perform complex, multi-step workflows.

To trigger the full Ubuntu installation and Kubernetes deployment workflow, use the following prompt, replacing the URL with the location of your instruction file:
```
Follow the instructions in this document that is on an nginx server: [http://100.80.20.18:8080/prompt.txt]
```

## 🛠️ Agent Tools

The agent has access to the following tools:

| Tool Name | Description |
| :--- | :--- |
| `get_server_status` | Retrieves the power state, health status, and model/serial number from a server's iDRAC. |
| `set_server_power_state` | Sets the server's power state (e.g., On, ForceOff, GracefulShutdown). |
| `get_bios_settings` | Fetches all BIOS attributes from the iDRAC. |
| `set_bios_settings` | Applies a dictionary of new values to the BIOS settings. |
| `get_raid_configuration` | Discovers the complete RAID setup, including controllers, virtual disks, and physical disks. |
| `create_raid_virtual_disk` | Creates a new virtual disk with a specified RAID level on a given controller. |
| `create_redfish_session` | Establishes a persistent session with iDRAC to get an auth token for subsequent requests. |
| `mount_virtual_media_iso_with_token` | Mounts a network-accessible ISO image to the server's virtual CD/DVD drive using a session token. |
| `eject_idrac_virtual_media` | Ejects the virtual media from the iDRAC. |
| `set_one_time_boot_to_virtual_cd` | Configures the server to boot from a specified device (like 'Cd' or 'Pxe') on the next restart. |
| `get_idrac_job_status` | Polls an iDRAC task URI to check the status of an asynchronous job (e.g., RAID creation). |
| `run_remote_command` | Executes a single shell command on a remote host via SSH. |
| `run_remote_script` | Uploads and executes a multi-line script on a remote host via SSH. |
| `upload_file` | Uploads a local file to a remote host via SFTP. |
| `download_file` | Downloads a file from a remote host via SFTP. |
| `get_remote_file_content` | Reads the content of a file on a remote server and returns it as a string. |
| `check_network_connectivity` | Checks if a TCP port is open on a given hostname to test connectivity. |
| `read_file_from_nginx` | Fetches the content of a text file from a web server. |
| `tavily_search` | A general-purpose search tool for finding information on the web. |

