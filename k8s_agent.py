import os

os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "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"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
os.environ["LANGCHAIN_PROJECT"] = "My K8s Agent"

import getpass
import io
import redfish
import paramiko
import requests
import json
import socket
import urllib3
import uuid
from typing import Dict, Union
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from langchain_core.messages import HumanMessage, AIMessage
from langchain_tavily import TavilySearch
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from langchain.tools import tool
from langchain_openai import ChatOpenAI

os.environ["GOOGLE_API_KEY"] = "AIzaSyA-AtjTPId8JnaA3y1Tv7j40KO-W6wBpak"
os.environ["TAVILY_API_KEY"] = "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"
os.environ["THIRD_PARTY_API_BASE"] = "http://100.80.20.5:4000/v1"

model = ChatOpenAI(
    model="deepseek-ai/DeepSeek-V3-0324",
    api_key="not_needed",
    base_url=os.environ.get("THIRD_PARTY_API_BASE")
)

proxy_host = '100.80.20.9'
proxy_port = 3389

"""
Creating tools for k8s LLM agent
------------------------------
"""
search = TavilySearch(max_results=2)

@tool    
def get_server_status(idrac_ip: str, idrac_user: str, idrac_password: str) -> dict:
    """
    Executes the tool to get the server status

    Args:
        idrac_ip: IP address of the iDRAC
        idrac_user: The username for iDRAC
        idrac_password: The password for iDRAC

    Returns:
        A dictionary containing server status information or an error message.
    """
    system_id = "System.Embedded.1"
    redfish_url = f"https://{idrac_ip}/redfish/v1/Systems/{system_id}"

    status_info = {
        "power_state": None,
        "health_status": None,
        "model": None,
        "serial_number": None,
        "error": None
    }

    try:
        # make the get request to the Redfish API
        response = requests.get(
            redfish_url,
            auth=(idrac_user, idrac_password),
            verify=False,
            timeout=90
        )

        # check if request was successful
        response.raise_for_status()

        # parse the JSON response
        data = response.json()

        # Extract relevant information
        status_info["power_state"] = data.get("PowerState")
        if "Status" in data and isinstance(data["Status"], dict):
            status_info["health_status"] = data["Status"].get("Health")

        status_info["model"] = data.get("Model")
        status_info["serial_number"] = data.get("SKU")
        if not status_info["serial_number"]:
            status_info["serial_number"] = data.get("SerialNumber")

    except requests.exceptions.HTTPError as http_err:
        status_info["error"] = f"HTTP error occurred: {http_err} - Response: {response.text if response else 'No response'}"
    except requests.exceptions.ConnectionError as conn_err:
        status_info["error"] = f"Connection error occurred: {conn_err}"
    except requests.exceptions.Timeout as timeout_err:
        status_info["error"] = f"Timeout error ocurred: {timeout_err}"
    except requests.exceptions.RequestException as req_err:
        status_info["error"] = f"An unexpected error occurred: {req_err}"
    except json.JSONDecodeError:
        status_info["error"] = "Failed to decode JSON response from iDRAC."
    except Exception as e:
        status_info["error"] = f"An unknown error occurred: {str(e)}"
    
    return status_info


ALLOWED_POWER_ACTIONS = [
    "On",
    "ForceOff",
    "GracefulShutdown",
    "ForceRestart",
    "GracefulRestart"
]

@tool
def set_server_power_state(idrac_ip, idrac_user, idrac_password, power_action: str) -> dict:
    """
    Executes the tool to set the server's power state. Can perform the following power actions: 'On', 'ForceOff', 'GracefulShutdown', 'ForceRestart', 'GracefulRestart'.

    Args:
        idrac_ip: IP address of the iDRAC
        idrac_user: The username for iDRAC
        idrac_password: The password for iDRAC
        power_action: The desired power action (e.g., "On", "ForceOff").

    Returns:
        A dictionary indicating success or failure and a message.
    """
    result = {
        "success": False,
        "message": "",
        "http_status_code": None
    }

    if power_action not in ALLOWED_POWER_ACTIONS:
        result["message"] = f"Invalid power_action: '{power_action}'. Allowed actions are: {', '.join(ALLOWED_POWER_ACTIONS)}"
        return result
    
    system_id = "System.Embedded.1"
    action_url = f"https://{idrac_ip}/redfish/v1/Systems/{system_id}/Actions/ComputerSystem.Reset"

    payload = {
        "ResetType": power_action
    }

    try:
        # Make the post request to the Redfish API
        response = requests.post(
            action_url,
            auth=(idrac_user, idrac_password),
            json=payload,
            verify=False,
            timeout=70
        )
        result["http_status_code"] = response.status_code

        # check if request was successful
        if response.status_code in [200, 202, 204]:
            result["success"] = True
            result["message"] = f"Power action '{power_action}' initiated successfully. HTTP Status: {response.status_code}"
            if response.text:
                try:
                    response_data = response.json()
                    if response_data and isinstance(response_data, dict) and response_data.get("error"):
                        # check for Redfish error message in the response body
                        error_info = response_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                        message_id = error_info.get("MessageId")
                        message_text = error_info.get("Message")
                        if message_id or message_text:
                            result["success"] = False
                            result["message"] = f"iDRAC reported error for action '{power_action}': {message_id} - {message_text}. HTTP Status: {response.status_code}"
                    elif response_data:
                        result["message"] += f" Response: {json.dumps(response_data)}"

                except json.JSONDecodeError:
                    result["message"] += f" Response: {response.text}"

        else:
            response_text = response.text
            try:
                error_data = response.json()
                # Try to parse standard Redfish error
                if error_data and isinstance(error_data, dict) and error_data.get("error"):
                    error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                    message_id = error_info.get("MessageId")
                    message_text = error_info.get("Message")
                    if message_id or message_text:
                        response_text = f"Redfish Error: {message_id} - {message_text}"
            except json.JSONDecodeError:
                pass # Use raw text if not JSON

            result["message"] = f"Failed to initiate power action '{power_action}'. HTTP Status: {response.status_code}. Response: {response_text}"
            response.raise_for_status() # this will raise an HTTPError for bad status codes

    except requests.exceptions.HTTPError as http_err:
        if not result["message"]:
            result["message"] = f"HTTP error occurred: {http_err}"
    except requests.exceptions.ConnectionError as conn_err:
        result["message"] = f"Connection error occurred: {conn_err}"
        result["http_status_code"] = None
    except requests.exceptions.Timeout as timeout_err:
        result["message"] = f"Timeout error occurred: {timeout_err}"
        result["http_status_code"] = None
    except requests.exceptions.RequestException as req_err:
        result["message"] = f"An unexpected error occurred during request: {req_err}"
        result["http_status_code"] = None
    except Exception as e:
        result["message"] = f"An unknown error occurred: {str(e)}"
        result["http_status_code"] = None

    return result


@tool
def get_bios_settings(idrac_ip, idrac_user, idrac_password) -> dict:
    """
    A tool that retrieves BIOS settings from an iDRAC IP using the Redfish API
    
    Args:
        idrac_ip: IP address of the iDRAC
        idrac_user: The username for iDRAC
        idrac_password: The password for iDRAC

    Returns:
        A dictionary containing BIOS settings or an error message
    """
    system_id = "System.Embedded.1"
    bios_url = f"https://{idrac_ip}/redfish/v1/Systems/{system_id}/Bios"

    result = {
        "bios_settings": None,
        "error": None
    }

    try:
        # Make get request to Redfish API
        response = requests.get(
            bios_url,
            auth=(idrac_user, idrac_password),
            verify=False,
            timeout=20
        )

        # check if request was successful
        response.raise_for_status()
        
        # parse the JSON response
        data = response.json()

        # extract BIOS attributes
        # for iDRAC, these are typically under the "Attributes" key in this response
        if "Attributes" in data and isinstance(data["Attributes"], dict):
            result["bios_setings"] = data["Attributes"]
        else:
            result["error"] = "Bios attributes not found in the expected format in the iDRAC response. The 'Attributes' kkey was missing or not a dictionary."
    
    except requests.exceptions.HTTPError as http_err:
        response_text = http_err.response.text if http_err.response else "No response body"
        try:
            error_data = json.loads(response_text)
            if error_data and isinstance(error_data, dict) and error_data.get("error"):
                error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                message_id = error_info.get("MessageId")
                message_text = error_info.get("Message")
                if message_id or message_text:
                    response_text = f"Redfish Error: {message_id} - {message_text}"
        except json.JSONDecodeError:
            pass # use raw text if not JSON
        result["error"] = f"HTTP error occurred: {http_err.response.status_code if http_err.response else 'Uknown Status'} - {response_text}"

    except requests.exceptions.ConnectionError as conn_err:
        result["error"] = f"Connection error occurred: {conn_err}"
    except requests.exceptions.Timeout as timeout_err:
        result["error"] = f"Timeout error occurred: {timeout_err}"
    except requests.exceptions.RequestException as req_err:
        result["error"] = f"An unexpected error occurred during request: {req_err}"
    except json.JSONDecodeError:
        result["error"] = "Failed to decode JSON response from iDRAC."
    except Exception as e:
        result["error"] = f"An unknown error occurred: {str(e)}"

    return result

@tool
def set_bios_settings(idrac_ip, idrac_user, idrac_password, settings_to_apply: dict) -> dict:
    """ 
    A tool that sets BIOS settings to the given values

    Args: 
        idrac_ip: IP address of iDRAC
        idrac_user: The username for iDRAC
        idrac_password: The password for iDRAC
        settings_to_apply: A dictionary of BIOS attribute names and their desired values.

    Returns:
        A dictionary containing the outcome of the request.
    """

    system_id = "System.Embedded.1"
    bios_settings_url = f"https://{idrac_ip}/redfish/v1/Systems/{system_id}/Bios/Settings"

    result = {
        "success": False,
        "message": "",
        "task_uri": None,
        "http_status_code": None,
        "reboot_required_for_full_apply": True # assume true for BIOS changes
    }

    if not isinstance(settings_to_apply, dict) or not settings_to_apply:
        result["message"] = "Error: 'settings_to_apply' must be a non-empty dictionary."
        return result
    
    payload = {
        "Attributes": settings_to_apply
    }

    try:
        # make the patch request to Redfish API
        response = requests.patch(
            bios_settings_url,
            auth=(idrac_user, idrac_password),
            json=payload,
            verify=False,
            timeout=45
        )
        result["http_status_code"] = response.status_code

        # successful requests for actions often return 200 OK or 202 Accepted
        if response.status_code in [200, 202]:
            result["success"] = True
            result["message"] = f"Request to stage BIOS settings accepted by iDRAC. HTTP Status: {response.status_code}."

            # check for a task URI in the Location header (common for 202)
            if 'Location' in response.headers:
                result["task_uri"] = response.headers['Location']
                result["message"] += f" iDRAC task created: {result['task_uri']}"

            # check response body for additional task info or messages
            try:
                response_data = response.json()
                if response_data:
                    if isinstance(response_data, list) and len(response_data) > 0 and "MessageID" in response_data[0]:
                        if response_data[0]["MessageID"] == "PR19":
                            job_id = response_data[0].get("MessageArgs", [None])[0]
                            if job_id:
                                result["message"] += f" Dell Job ID: {job_id} created to apply settings (usually on next reboot)."
                                if not result["task_uri"]: # fallback if location header is missing but job id is present
                                    result["task_uri"] = f"https://{idrac_ip}/redfish/v1/TaskService/Tasks/{job_id}"

                    # Standard Redfish error in success response body (less common but possible)
                    elif isinstance(response_data, dict) and response_data.get("error"):
                        error_info = response_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                        message_id = error_info.get("MessageId")
                        message_text = error_info.get("Message")
                        if message_id or message_text:
                            result["success"] = False # it was an error message
                            result["message"] = f"iDRAC reported error in response: {message_id} - {message_text}."
                    elif response_data:
                        result["message"] += f" Response Body: {json.dumps(response_data)}"
            except json.JSONDecodeError:
                if response.text:
                    result["message"] += f" Non-JSON Response Body: {response.text}"

            result["message"] += " A server reboot is typically required for these settings to take full effect."           

        else:
            # handle error responses
            response_text = response.text
            try:
                error_data = response.json()
                if error_data and isinstance(error_data, dict) and error_data.get("error"):
                    error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                    message_id = error_info.get("MessageId")
                    message_text = error_info.get("Message")
                    if message_id or message_text:
                        response_text = f"Redfish Error: {message_id} - {message_text}"
            except json.JSONDecodeError:
                pass # use raw text if not JSON
            result["message"] = f"Failed to stage BIOS settings. HTTP Status: {response.status_code}. Respose: {response_text}"
            # response.raise_for_status() # Let the caller decide if to raise based on success flag
    
    except requests.exceptions.HTTPError as http_err:
        if not result["message"]:
            result["message"] = f"HTTP error occurred: {http_err}"
    except requests.exceptions.ConnectionError as conn_err:
        result["message"] = f"Connection error occurred: {conn_err}"
        result["http_status_code"] = None
    except requests.exceptions.Timeout as timeout_err:
        result["message"] = f"Timeout error occurred: {timeout_err}"
        result["http_status_code"] = None
    except requests.exceptions.RequestException as req_err:
        result["message"] = f"An unexpected error occurred during reques: {req_err}"
        result["http_status_code"] = None
    except Exception as e:
        result["message"] = f"An unknown error occurred: {str(e)}"
        result["http_status_code"] = None

    return result

@tool
def create_redfish_session(idrac_ip: str, idrac_user: str, idrac_password: str) -> str | None:
    """
    Creates a Redfish session and returns the authentication token.

    Args:
        idrac_ip: The IP address of the iDRAC.
        idrac_user: The username for iDRAC.
        idrac_password: The password for iDRAC.

    Returns:
        The session's X-Auth-Token string if successful, otherwise None.
    """
    session_url = f"https://{idrac_ip}/redfish/v1/SessionService/Sessions"
    payload = {
        "UserName": idrac_user,
        "Password": idrac_password
    }

    print(f"Attempting to create a Redfish session on {idrac_ip}...")
    
    try:
        response = requests.post(
            session_url,
            json=payload,
            verify=False,  # Set to True if iDRAC has a trusted certificate
            timeout=30
        )
        response.raise_for_status()  # Raise an exception for bad status codes

        auth_token = response.headers.get("X-Auth-Token")
        if not auth_token:
            print("Error: Session created, but X-Auth-Token was not found in the response headers.")
            return None
        
        print("Success: Session created successfully.")
        return auth_token

    except requests.exceptions.RequestException as e:
        print(f"Error creating session: {e}")
        return None

@tool
def mount_virtual_media_iso_with_token(idrac_ip: str, auth_token: str, image_url: str) -> dict:
    """ 
    A tool to insert virtual media (e.g., an ISO)
    into the virtual CD/DVD drive of a Dell iDRAC using a Redfish session token.

    Args: 
        idrac_ip: The IP address of the iDRAC.
        auth_token: The Redfish X-Auth-Token for the active session.
        image_url: The network-accessible URL of the ISO image.

    Returns:
        A dictionary containing the outcome of the request.
    """
    # --- MODIFICATION START ---
    # The function now accepts `auth_token` instead of user/password.
    # The `auth` parameter in the requests.post call is replaced with a `headers` dictionary.
    # --- MODIFICATION END ---
    
    manager_id = "iDRAC.Embedded.1"
    media_type = "CD"
    # This action URL is specific to Dell iDRACs
    action_url = f"https://{idrac_ip}/redfish/v1/Managers/{manager_id}/VirtualMedia/{media_type}/Actions/VirtualMedia.InsertMedia"

    result = {
        "success": False,
        "message": "",
        "http_status_code": None
    }

    if not all([auth_token, image_url]):
        result["message"] = "Error: 'auth_token' and 'image_url' cannot be empty."
        return result
    
    payload = {
        "Image": image_url
    }
    
    # The header now includes the session token for authentication
    headers = {
        "X-Auth-Token": auth_token,
        "Content-Type": "application/json"
    }

    try:
        # Make the POST request to the Redfish API action
        response = requests.post(
            action_url,
            headers=headers,  # Use the token in the headers
            json=payload,
            verify=False,     # Set to True if iDRAC has a trusted certificate
            timeout=80
        )
        result["http_status_code"] = response.status_code

        # A 2xx status code indicates the request was accepted
        if response.status_code in [200, 202, 204]:
            result["success"] = True
            result["message"] = f"Request to insert virtual media from '{image_url}' was accepted by iDRAC. HTTP Status: {response.status_code}."
        
        else:
            # Try to parse the specific Redfish error message for better feedback
            response_text = response.text
            try:
                error_data = response.json()
                if error_data and isinstance(error_data, dict) and error_data.get("error"):
                    error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                    message_id = error_info.get("MessageId")
                    message_text = error_info.get("Message")
                    if message_id or message_text:
                        response_text = f"Redfish Error: {message_id} - {message_text}"
            except json.JSONDecodeError:
                # If the response isn't valid JSON, use the raw text
                pass
            result["message"] = f"Failed to insert virtual media. HTTP Status: {response.status_code}. Response: {response_text}"

    except requests.exceptions.HTTPError as http_err:
        result["message"] = f"HTTP error occurred: {http_err}"
    except requests.exceptions.ConnectionError as conn_err:
        result["message"] = f"Connection error occurred: {conn_err}"
    except requests.exceptions.Timeout as timeout_err:
        result["message"] = f"Timeout error occurred: {timeout_err}"
    except requests.exceptions.RequestException as req_err:
        result["message"] = f"An unexpected error occurred during request: {req_err}"
    except Exception as e:
        result["message"] = f"An unknown error occurred: {str(e)}"
    
    return result



@tool
def set_one_time_boot_to_virtual_cd(idrac_ip, idrac_user, idrac_password, boot_target: str) -> bool:
    """ 
    A tool to set the one-time boot source on a Dell iDRAC using the Redfish API. 
    This is typically used to boot from virtual media for an OS installation.

    Args:
        irac_ip: The IP address of the iDRAC.
        idrac_user: The username for iDRAC.
        idrac_password: The password for iDRAC.
        boot_target: The target device to boot from (e.g., 'Cd', 'Pxe').

    Returns:
        A dictionary containing the outcome of the request.
    """

    ALLOWED_TARGETS = [
        "None",         # Boot from the default boot order.
        "Pxe",          # Boot from the network (PXE).
        "Cd",           # Boot from the virtual or physical CD/DVD drive.
        "Hdd",          # Boot from the first hard drive.
        "Usb",          # Boot from a USB device.
        "Diags",        # Boot to the diagnostics partition.
        "UefiShell",    # Boot to the UEFI Shell.
        "UefiHttp"      # Boot from a URL.
    ]

    system_id = "System.Embedded.1"
    system_url = f"https://{idrac_ip}/redfish/v1/Systems/{system_id}"

    result = {
        "success": False,
        "message": "",
        "http_status_code": None
    }

    if boot_target not in ALLOWED_TARGETS:
        result["message"] = f"Invalid boot_target: '{boot_target}'. Allowed targets are: {', '.join(ALLOWED_TARGETS)}"
        return result
    
    # this payload sets the target device and ensures it is a one-time setting.
    payload = {
        "Boot": {
            "BootSourceOverrideTarget": boot_target,
            "BootSourceOverrideEnabled": "Once"
        }
    }

    try:
        # make the patch request to the Redfish API
        response = requests.patch(
            system_url,
            auth=(idrac_user, idrac_password),
            json=payload,
            verify=False,
            timeout=30
        )
        result["http_status_code"] = response.status_code

        if response.status_code == 200:
            result["success"] = True
            result["message"] = f"Successfully set one-time boot to '{boot_target}'. This will take effect on the next server reboot."
        else:
            response_text = response.text
            try:
                error_data = response.json()
                if error_data and isinstance(error_data, dict) and error_data.get("error"):
                    error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0] 
                    message_id = error_info.get("MessageId")
                    message_text = error_info.get("Message")
                    if message_id or message_text:
                        response_text = f"Redfish Error: {message_id} - {message_text}"
            except json.JSONDecodeError:
                pass
            result["message"] = f"Failed to set one-time boot. HTTP Status: {response.status_code}. Response: {response_text}"

    except requests.exceptions.HTTPError as http_err:
        result["message"] = f"HTTP error occurred: {http_err}"
    except requests.exceptions.ConnectionError as conn_err:
        result["message"] = f"Connection error occurred: {conn_err}"
        result["http_status_code"] = None
    except requests.exceptions.Timeout as timeout_err:
        result["message"] = f"Timeout error occurred: {timeout_err}"
        result["http_status_code"] = None
    except requests.exceptions.RequestException as req_err:
        result["message"] = f"An unexpected error occurred during request: {req_err}"
        result["http_status_code"] = None
    except Exception as e:
        result["message"] = f"An unknown error occurred: {str(e)}"
        result["http_status_code"] = None

    return result 

@tool
def get_raid_configuration(idrac_ip, idrac_user, idrac_password) -> list:
    """ 
    A tool that navigates the Redfish API to discover and report the full RAID configuration of a Dell server.

    Args:
        idrac_ip: The IP address of the iDRAC
        idrac_user: The username for iDRAC
        idrac_password: The password for iDRAC

    Returns:
        A dictionary containing the structured RAID configuration or an error message.
    """

    # --------------Nested Helper Functions---------------------
    def _make_redfish_get_request(url: str, auth: tuple, timeout: int = 20) -> dict:
        """ Helper function to make a GET request and handle basic response validation"""
        response = requests.get(url, auth=auth, verify=False, timeout=timeout)
        response.raise_for_status() # Raise HTTPError for bad responses
        return response.json()
    
    def _bytes_to_gb(size_bytes):
        """ Helper to convert bytes to gigabytes for readability. """
        if size_bytes is None or not isinstance(size_bytes, (int, float)) or size_bytes < 0:
            return None
        if size_bytes == 0:
            return 0
        # use 1000^3 for GB as per storage marketing standards, not GiB (1024^3)
        return round(size_bytes / (1000 ** 3), 2)
    
    # ----- Main function -----
    base_url = f"https://{idrac_ip}"
    auth = (idrac_user, idrac_password)
    final_config = {"controllers": [], "error": None}

    try:
        # 1. Get the lsit of storage subsystems
        storage_entry_url = f"{base_url}/redfish/v1/Systems/System.Embedded.1/Storage"
        storage_systems = _make_redfish_get_request(storage_entry_url, auth)

        for member in storage_systems.get("Members", []):
            controller_url = f"{base_url}{member['@odata.id']}"
            controller_details = _make_redfish_get_request(controller_url, auth)

            if not controller_details.get("volumes"):
                continue
            
            controller_info = {
                "id": controller_details.get("Id"),
                "model": controller_details.get("Name"),
                "status": controller_details.get("Status", {}).get("Health"),
                "virtual_disks": []
            }

            # 2. Get the list of virtual disks (volumes) for this controller
            volume_url = f"{base_url}{controller_details['Volumes']['@odata.id']}"
            volumes = _make_redfish_get_request(volume_url, auth)

            for volume_member in volumes.get("Members", []):
                volume_url = f"{base_url}{volume_member['@odata.id']}"
                volume_details = _make_redfish_get_request(volume_url, auth)

                virtual_disk_info = {
                    "id": volume_details.get("Id"),
                    "name":volume_details.get("Name"),
                    "raid_level": volume_details.get("RAIDType"),
                    "size_gb": _bytes_to_gb(volume_details.get("CapacityBytes")),
                    "status": volume_details.get("Status", {}).get("Health"),
                    "state": volume_details.get("Status", {}).get("State"),
                    "physical_disks": []
                }

                # 3. Get the physical disks associated with this virtual disk
                drives_links = volume_details.get("Links", {}).get("Drives", [])
                for drive_link in drives_links:
                    drive_url = f"{base_url}{drive_link['@odata.id']}"
                    drive_details = _make_redfish_get_request(drive_url, auth)

                    physical_disk_info = {
                        "id": drive_details.get("Id"),
                        "location": drive_details.get("Location", [{}])[0].get("Info"),
                        "media_type": drive_details.get("MediaType"),
                        "capacity_gb": _bytes_to_gb(drive_details.get("CapacityBytes")),
                        "status": drive_details.get("Status", {}).get("Health")
                    }
                    virtual_disk_info["physical_disks"].append(physical_disk_info)

                controller_info["virtual_disks"].append(virtual_disk_info)

            final_config["controllers"].append(controller_info)

    except requests.exceptions.HTTPError as http_err:
        final_config["error"] = f"HTTP error occurred: {http_err} - Check URL and permissions."
    except requests.exceptions.ConnectionError as conn_err:
        final_config["error"] = f"Connection error occurred: {conn_err} - Check iDRAC IP and network connectivity."
    except requests.exceptions.Timeout:
        final_config["error"] = "The request to the iDRAC timed out."
    except Exception as e:
        final_config["error"] = f"An unexpected error occurred: {e}"

    return final_config


@tool
def create_raid_virtual_disk(idrac_ip, idrac_user, idrac_password, controller_id: str, raid_level: str, physical_disk_ids: list[str], virtual_disk_name: str) -> dict:
    """ 
    Creates a new RAID virtual disk on a Dell iDRAC.

    Args:
        idrac_ip: The IP address of the iDRAC.
        idrac_user: The username for iDRAC.
        idrac_password: The password for iDRAC.
        controller_id: The ID of the target storage controller.
        raid_level: the desired RAID level.
        physical_disk_ids: A list of the IDs of the physcical disks to use.
        virtual_disk_name: A name for the new virtual disk.

    Returns:
        A dictionary containing the outcome of the request.
    """
    result = {
        "success": False,
        "message": "",
        "task_uri": None,
        "http_status_code": None
    }

    # Pre-flight validation -----
    raid_requirements = {
        "RAID-0": 1, "RAID-1": 2, "RAID-5": 3, "RAID-6": 4, "RAID-10": 4
    }
    raid_level_upper = raid_level.upper().replace(" ", "")
    if raid_level_upper not in raid_requirements:
        result["message"] = f"Unsupported RAID level '{raid_level}'. Supported levels are: {', '.join(raid_requirements.keys())}"
        return result
    
    min_disks = raid_requirements[raid_level_upper]
    if len(physical_disk_ids) < min_disks:
        result["message"] = f"Not enough disks for {raid_level_upper}. Requires at least {min_disks}, but only {len(physical_disk_ids)} were provided."
        return result
    
    if raid_level_upper == "RAID-1" and len(physical_disk_ids) != 2:
        result["message"] = f"RAID-1 requires exactly 2 disks. {len(physical_disk_ids)} were provided."
        return result

    if raid_level_upper == "RAID-10" and len(physical_disk_ids) % 2 != 0:
        result["message"] = f"RAID-10 requires an even number of disks (minimum 4). {len(physical_disk_ids)} were provided."
        return result

    # --- Construct payload and URL ---
    volumes_url = f"https://{idrac_ip}/redfish/v1/Systems/System.Embedded.1/Storage/{controller_id}/Volumes"

    # Construct the list of drive links for the payload
    drive_links = [{"@odata.id": f"/redfish/v1/Systems/System.Embedded.1/Storge/{controller_id}/Drives/{disk_id}"} for disk_id in physical_disk_ids]

    payload = {
        "Name": virtual_disk_name,
        "RAIDType": raid_level_upper,
        "Links": {
            "Drives": drive_links
        }
    }

    try:
        # Make the post request to the Redfish API
        response = requests.post(
            volumes_url,
            auth=(idrac_user, idrac_password),
            json=payload,
            verify=False,
            timeout=45
        )
        result["http_status_code"] = response.status_code

        if response.status_code == 202:
            result["success"] = True
            result["message"] = f"Request to create virtual disk '{virtual_disk_name}' was accepted. An iDRAC job has been created."

            # The task URI is critical for monitoring job completion.
            if 'Location' in response.headers:
                result["task_uri"] = f"https://{idrac_ip}{response.headers['Location']}"
                result["message"] = f" Monitor the task at: {result['task_uri']}"
            else:
                result["message"] += " Warning: No task URI found in response headers. Cannot monitor job status automaticaly."

        else:
            # Handle error responses
            response_text = response.text
            try:
                error_data = response.json()
                if error_data and isinstance(error_data, dict) and error_data.get("error"):
                    error_info = error_data.get("error", {}).get("@Message.ExtendedInfo", [{}])[0]
                    message_id = error_info.get("MessageId")
                    message_text = error_info.get("Message")
                    if message_id or message_text:
                        response_text = f"Redfish Error: {message_id} - {message_text}"
            except json.JSONDecodeError:
                pass
            result["message"] = f"Failed to create virtual disk. HTTP Status: {response.status_code}. Response: {response_text}"
            
    except requests.exceptions.RequestException as e:
        result["message"] = f"An unexpected network error occurred: {e}"
    except Exception as e:
        result["message"] = f"An unknown error occurred: {e}"

    return result


@tool
def run_remote_command(hostname, username, password_or_key, command: str, port=22, timeout=300) -> dict:
    """ 
    A tool that connects to a remote host via SSH and executes a command.
    
    This function attempts to determine whether password_or_key is a password
    or a private key string and authenticates accordingly.

    Args:
        hostname: The IP address or hostname of the server.
        username: The username for authentication.
        password_or_key: The password string or the private key string.
        command: The command to execute.
        port: The SSH port.
        timeout: Timeout for connection and command execution in seconds.

    Returns:
        A dictionary containing stdout, stderr, exit_code, and any conection/execution error.
    """
    client = None
    result = {
        "stdout": None,
        "stderr": None,
        "exit_code": None,
        "error": None
    }

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        password = None

        # Heuristic to determine if the credential is a private key or a password.
        # This checks for the typical start of a PEM-formatted key.
        if '-----BEGIN' in password_or_key:
            # Load key from string content
            key_file_obj = io.StringIO(password_or_key)
            key_types = (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key)
            for key_type in key_types:
                try:
                    pkey = key_type.from_private_key(key_file_obj)
                    break
                except paramiko.SSHException:
                    key_file_obj.seek(0)

            if not pkey:
                result["error"] = "The provided private key is invalid, unsupported, or possibly encrypted."
                return result
        else:
            password = password_or_key

        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

        result["exit_code"] = stdout.channel.recv_exit_status()
        result["stdout"] = stdout.read().decode('utf-8').strip()
        result["stderr"] = stderr.read().decode('utf-8').strip()
       
    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed. Please check username and password/key."
    except paramiko.SSHException as ssh_ex:
        result["error"] = f"SSH error occurred: {ssh_ex}"
    except socket.timeout:
        result["error"] = f"Connection or command timed out after {timeout} seconds."
    except socket.error as sock_ex:
        result["error"] = f"Network connection error: {sock_ex}"
    except Exception as e:
        result["error"] = f"An unexpected error occurred: {str(e)}"
    finally:
        if client:
            client.close()
    
    return result


@tool
def upload_file(hostname, username, password_or_key, local_path: str, remote_path: str, port=22) -> dict:
    """ 
    A tool that connects to a remote host via SSH and uploads a single file using SFTP.

    This function attempts to determine whether password_or_key is a password or a 
    private key string and authenticates accordingly.

    Args:
        hostname: The IP address or hostname of the server.
        username: The username for authentication.
        password_or_key: The password string or the private key string.
        local_path: The path of the local file to send.
        remote_path: The destination path on the remote server.
        port: The SSH port.

    Returns:
        A dictionary containing a success boolean and a message.
    """
    client = None
    sftp = None
    result = {"success": False, "message": ""}

    try:
        # check if the local file exists before attempting to connect
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found at path: {local_path}")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        password = None

        if '-----BEGIN' in password_or_key:
            key_file_obj = io.StringIO(password_or_key)
            try:
                pkey = paramiko.Ed25519Key.from_private_key(key_file_obj)
            except paramiko.SSHException:
                key_file_obj.seek(0)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file_obj)
                except paramiko.SSHException:
                    key_file_obj.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file_obj)
            if not pkey:
                raise ValueError("Private key format is not recognized or is invalid.")
        else:
            password = password_or_key

        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=30
        )

        # Open an SFTP session
        sftp = client.open_sftp()

        # Upload the file
        sftp.put(local_path, remote_path)

        result["success"] = True
        result["message"] = f"Succesfully uploaded '{local_path}' to '{hostname}:{remote_path}'"

    except FileNotFoundError as fnf_err:
        result["message"] = str(fnf_err)
    except paramiko.AuthenticationException:
        result["message"] = "Authentication failed. Please check username and password/key."
    except paramiko.SSHException as ssh_ex:
        result["message"] = f"SSH error occurred: {ssh_ex}"
    except socket.timeout:
        result["message"] = "Connection timed out."
    except Exception as e:
        # This can catch SFTP-specific errors like 'permission denied' on the remote path
        result["message"] = f"An unexpected error occurred: {str(e)}"
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()
    
    return result


@tool
def download_file(hostname, username, password_or_key, remote_path: str, local_path: str, port=22) -> dict:
    """ 
    A tool that connects to a remote host via SSH and downloads a single file using SFTP.

    This function attempts to determine whether password_or_key is a password or a private
    key string and authenticates accordingly.

    Args:
        hostname: The IP address or hostname of the server.
        username: The username for authentication.
        password_or_key: The password string or the private key string.
        remote_path: The source path of the file on the remote server.
        local_path: The destination path on the local machine.
        port: The SSH port.

    Returns:
        A dictionary containing a success boolean and a message.
    """
    client = None
    sftp = None
    result = {"success": False, "message": ""}

    try:
        # Ensure the local directory exists, create it if it doesn't.
        local_dir = os.path.dirname(local_path)
        if local_dir and not os.path.exists(local_dir):
            os.makedirs(local_dir)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        password = None

        if '-----BEGIN' in password_or_key:
            key_file_obj = io.StringIO(password_or_key)
            try:
                pkey = paramiko.Ed25519Key.from_private_key(key_file_obj)
            except paramiko.SSHException:
                key_file_obj.seek(0)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file_obj)
                except paramiko.SSHException:
                    key_file_obj.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file_obj)
            if not pkey:
                raise ValueError("Privte key format is not recognized or is invalid.")
        else:
            password = password_or_key
        
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=30
        )

        sftp = client.open_sftp()

        # Download the file
        sftp.get(remote_path, local_path)

        result["success"] = True
        result["message"] = f"Successfully downloaded '{hostname}:{remote_path}' to '{local_path}'"

    except FileNotFoundError as fnf_err:
        # sftp.get raises FileNotFoundError if the remote file doesn't exist
        result["message"] = f"Remote file not found at '{remote_path}' or local path issue: {fnf_err}"
    except paramiko.AuthenticationException:
        result["message"] = "Authentication failed. Please check username and password/key."
    except paramiko.SSHException as ssh_ex:
        result["message"] = f"SSH error occurred: {ssh_ex}"
    except socket.timeout:
        result["message"] = "Connection timed out."
    except Exception as e:
        # This can catch other SFTP errors or local permission errors
        result["message"] = f"An unexpected error occurred: {str(e)}"
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()
    
    return result


@tool
def run_remote_script(hostname, username, password_or_key, script_content: str, interpreter: str = "/bin/bash", port=22, timeout=600) -> dict:
    """ 
    A tool that uploads the script_content to a temporary file on remote server and then execute it
    
    Args:
        hostname: The IP address or hostname of the server.
        username: The username for authentication.
        password_or_key: The password string or the private key string.
        script_content: The full content of the script to execute.
        interpreter: The interpreter to use (e.g., /bin/bash).
        port: The SSH port.
        timeout: Timeout for connection and command execution in seconds.

    Returns:
        A dictionary containing stdout, stderr, exit_code, and any connection/execution error.
    """
    client = None
    sftp = None
    result = {
        "stdout": None,
        "stderr": None,
        "exit_code": None,
        "error": None
    }

    # Generate a unique filename for the temporary script
    remote_temp_path = f"/tmp/mcp_script_{uuid.uuid4().hex}.sh"

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        password = None

        if '-----BEGIN' in password_or_key:
            key_file_obj = io.StringIO(password_or_key)
            try:
                pkey = paramiko.Ed25519Key.from_private_key(key_file_obj)
            except paramiko.SSHException:
                key_file_obj.seek(0)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file_obj)
                except paramiko.SSHException:
                    key_file_obj.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file_obj)
            if not pkey:
                raise ValueError("Private key format is not recognized or is invalid.")
        else:
            password = password_or_key

        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=30
        )
        sftp = client.open_sftp()

        # 1. Upload the script content to the temporary file
        with sftp.file(remote_temp_path, 'w') as remote_file:
            remote_file.write(script_content)

        # 2. Make the script excutable
        sftp.chmod(remote_temp_path, 0o755) # rwxr-xr-x

        # 3. Execute the script
        command_to_run = f"{interpreter} {remote_temp_path}"
        stdin, stdout, stderr = client.exec_command(command_to_run, timeout=timeout)

        result["stdout"] = stdout.read().decode('utf-8').strip()
        result["stderr"] = stderr.read().decode('utf-8').strip()
        result["exit_code"] = stdout.channel.recv_exit_status()

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed. Please check username and password/key."
    except paramiko.SSHException as ssh_ex:
        result["error"] = f"SSH error occurred: {ssh_ex}"
    except socket.timeout:
        result["error"] = f"Connection or script execution timed out after {timeout} seconds."
    except Exception as e:
        result["error"] = f"An unexpected error occurred: {str(e)}"
    finally:
        # 4. Clean up the remote script file, regardless of success or failure
        if sftp:
            try:
                sftp.remote(remote_temp_path)
            except Exception as e:
                # Append cleanup error to main error if one already exists
                cleanup_error = f"Failed to clean up remote script file '{remote_temp_path}': {e}"
                if result["error"]:
                    result["error"] += f"\n[CLEANUP WARNING]: {cleanup_error}"
                else:
                    result["stderr"] = (result["stderr"] or "") + f"\n[CLEANUP WARNING]: {cleanup_error}"
            sftp.close()
        if client:
            client.close()
    
    return result


@tool
def get_idrac_job_status(idrac_ip: str, idrac_user: str, idrac_password: str, task_uri: str) -> dict:
    """
    A tool that polls a specific task URI on an iDRAC to get the status of an asynchronous job

    Args:
        idrac_ip: The IP address of the iDRAC.
        idrac_user: The username for iDRAC.
        idrac_password: The password for iDRAC.
        task_uri: The URI of the task to check the status of.

    Returns:
        A dictionary containing the task state and any error messages. 
    """
    result = {
        "task_state": None, 
        "job_state": None, 
        "message": "",
        "error": None
    }
    full_url = f"https://{idrac_ip}{task_uri}"
    auth = (idrac_user, idrac_password)

    try:
        response = requests.get(full_url, auth=auth, verify=False, timeout=20)
        response.raise_for_status()
        data = response.json()

        result["task_state"] = data.get("TaskState")

        oem_data = data.get("Oem", {}).get("Dell", {}).get("DellJob", {})
        if oem_data:
            result["job_state"] = oem_data.get("JobState")

        # Get the most relevant message
        if data.get("Messages"):
            message_info = data["Messages"][0]
            result["message"] = message_info.get("Message", "No message content found.")

    except requests.exceptions.HTTPError as e:
        result["error"] = f"HTTP error polling task status: {e}"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Network error polling task status: {e}"
    except Exception as e:
        result["error"] = f"An unexpected error occurred: {e}"
        
    return result

@tool
def check_network_connectivity(hostname:str, port: int, timeout: int = 5) -> dict:
    """
    A tool that checks if a TCP port is open on a given host.
    """
    result = {"success": False, "message": ""}
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            result["success"] = True
            result["message"] = f"Successfully connected to {hostname} on port {port}."
    except socket.timeout:
        result["message"] = f"Connection to {hostname} on port {port} timed out after {timeout} seconds."
    except ConnectionRefusedError:
        result["message"] = f"Connection to {hostname} on port {port} was refused."
    except socket.gaierror:
        result["message"] = f"Hostname '{hostname}' could not be resolved."
    except Exception as e:
        result["message"] = f"An unexpected error occurred: {e}"

    return result

@tool
def eject_idrac_virtual_media(idrac_ip: str, idrac_user: str, idrac_password: str) -> dict:
    """
    A tool that ejects the virtual media from the iDRAC's virtual CD drive.

    Args:
        idrac_ip: The IP address of the iDRAC.
        idrac_user: The username for iDRAC.
        idrac_password: The password for iDRAC.

    Returns:
        A dictionary with the outcome of the action.
    """
    manager_id = "iDRAC.Embedded.1"
    media_type = "CD"
    action_url = f"https://{idrac_ip}/redfish/v1/Managers/{manager_id}/VirtualMedia/{media_type}/Actions/VirtualMedia.EjectMedia"
    result = {"success": False, "message": "", "http_status_code": None}
    auth = (idrac_user, idrac_password)

    try:
        # The payload for EjectMedia is an empty JSON object.
        response = requests.post(action_url, auth=auth, json={}, verify=False, timeout=30)
        result["http_status_code"] = response.status_code

        if response.status_code in [200, 202, 204]:
            result["success"] = True
            result["message"] = f"Request to eject virtual media was accepted by iDRAC. HTTP Status: {response.status_code}."
        else:
            result["message"] = f"Failed to eject virtual media. HTTP Status: {response.status_code}. Response: {response.text}"
    except requests.exceptions.RequestException as e:
        result["message"] = f"An unexpected network error occurred: {e}"
    except Exception as e:
        result["message"] = f"An unknown error occurred: {e}"

    return result     

@tool
def get_remote_file_content(hostname: str, username: str, password_or_key: str, remote_path: str, port: int = 22) -> dict:
    """
    A tool that reads the content of a remote file and returns it as a string.
    """
    result = {"content": None, "error": None}
    client = None
    sftp = None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        password = None
        if '-----BEGIN' in password_or_key:
            key_file_obj = io.StringIO(password_or_key)
            # Add robust key type checking
            for key_class in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]:
                try:
                    key_file_obj.seek(0)
                    pkey = key_class.from_private_key(key_file_obj)
                    break
                except paramiko.SSHException:
                    continue
            if not pkey: raise ValueError("Private key format is not recognized or is invalid.")
        else:
            password = password_or_key

        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=30
        )
        sftp = client.open_sftp()

        with sftp.open(remote_path, 'r') as remote_file:
            result["content"] = remote_file.read().decode('utf-8')

    except FileNotFoundError:
        result["error"] = f"Remote file not found at '{remote_path}'."
    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed. Please check username and password/key."
    except Exception as e:
        result["error"] = f"An unexpected error occurred: {str(e)}"
    finally:
        if sftp: sftp.close()
        if client: client.close()

    return result

@tool
def read_file_from_nginx(url: str) -> Dict[str, Union[bool, str]]:
    """
    Fetches the content of a text file from a web server and returns a structured dictionary.

    This tool is designed for an agent to reliably read instructions or configurations 
    from a plain text file hosted on a web server like NGINX.

    Args:
        url: The full URL of the text file to read. 
             For example: "http://192.168.1.50/instructions.txt"

    Returns:
        A dictionary with the following structure:
        - On success: {'success': True, 'content': '<file_content>'}
        - On failure: {'success': False, 'error': '<error_message>'}
    """
    timeout_seconds = 15
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    print(f"Attempting to fetch content from URL: {url}")

    try:
        response = requests.get(url, timeout=timeout_seconds, headers=headers)
        response.raise_for_status()

        print("Successfully fetched file content.")
        return {
            'success': True,
            'content': response.text
        }

    except requests.exceptions.HTTPError as http_err:
        error_message = f"HTTP Error: Status code {http_err.response.status_code}. The URL may be incorrect or the file may not exist."
        print(error_message)
        return {'success': False, 'error': error_message}
        
    except requests.exceptions.ConnectionError as conn_err:
        error_message = f"Connection Error: Could not connect to the server. Please check the hostname or IP address and ensure the server is running."
        print(error_message)
        return {'success': False, 'error': error_message}

    except requests.exceptions.Timeout as timeout_err:
        error_message = f"Timeout Error: The server did not respond within {timeout_seconds} seconds."
        print(error_message)
        return {'success': False, 'error': error_message}

    except requests.exceptions.RequestException as req_err:
        error_message = f"An unexpected request error occurred: {req_err}."
        print(error_message)
        return {'success': False, 'error': error_message}


# add more tools here as they're created
tools = [search, get_server_status, set_server_power_state, 
         create_redfish_session, mount_virtual_media_iso_with_token, 
         set_one_time_boot_to_virtual_cd, run_remote_command, 
         run_remote_script, get_idrac_job_status, 
         eject_idrac_virtual_media, read_file_from_nginx]



# allow the agent to recall conversations
memory = MemorySaver()

# create the agent
agent = create_react_agent(model, tools, checkpointer=memory)


config = {"configurable": {"thread_id": "abc123"}}
config["recursion_limit"] = 50


# ------ Using agent ------
def main():
    conversation_history = []

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["quit", "exit"]:
            print("Ending chat.")
            break

        conversation_history.append(HumanMessage(content=user_input))

        print("\nAgent: ", end="", flush=True)

        full_response_content = ""
        final_ai_message = None

        try:
            for chunk in agent.stream({"messages": conversation_history}, config=config):
                if "output" in chunk:
                    print(chunk["output"], end="", flush=True)
                    full_response_content += chunk["output"]
            
            print()

            if full_response_content:
                conversation_history.append(AIMessage(content=full_response_content))

        except Exception as e:
            print(f"An error occurred: {e}")
            conversation_history.pop()

if __name__ == "__main__":
    main()



"""
To use the agent for installing Ubuntu and 
deploying a Kubernetes cluster, give it this prompt:
(copy the whole line)
--------------------------------------------------------

Follow the instructions in this document that is on an nginx server: http://100.80.20.18:8080/prompt.txt
"""


