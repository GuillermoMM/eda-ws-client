# eda-ws-client

## Description

`eda-ws-client` Script that initiates an insecure WebSocket connection to EDA, periodically sending messages at a defined interval to retrieve telemetry data from EDB.
The intention of this script is not to duplicate the edactl query features and or provide a full e2e application, this script is just for educational and demo purpose.

## Requirements

- **Go** version **1.22** or higher (may work with other versions)
- **Tested on** EDA **24.12.1/2** (using new Keycloak authentication)
- **Linux machine** (can be compiled for other operating systems)

## Usage

### 1. Clone the Project

```sh
 git clone <repository_url>
 cd eda-ws-client
```

### 2. Configure `config.json`

Modify the variables in `config.json` to match your setup. Pay special attention to:

- `serverURL`, `authURL`, and `apiBaseURL`: `<EDA_IP>:<Port>`
- `client_secret`: Can be obtained from Keycloak.
    For more details on obtaining the **Keycloak secret**, refer to the [official documentation](https://docs.eda.dev/development/api/#authentication).
- `username` and `password`: Your authentication credentials.
- `namespace`: Define the namespace.
- `query`: Define any **EQL query** you want to retrieve.
- `messageinterval`: How often telemetry data should be queried in seconds.

#### Example `config.json`

```json
{
    "serverURL": "wss://100.108.1.31:443/events",
    "authURL": "https://100.108.1.31:443/core/httpproxy/v1/keycloak/realms/eda/protocol/openid-connect/token",
    "username": "admin",
    "password": "admin",
    "apiBaseURL": "https://100.108.1.31:443/core/query/v1/eql",
    "query": ".namespace.node.srl.interface.traffic-rate where (.namespace.node.name = 'leaf1' and .namespace.node.srl.interface.name = 'ethernet-1/1')",
    "client_id": "eda",
    "client_secret": "hxLxq16cvtrQBi0V9oANeL81N5xFun5x",
    "messageinterval": 0.5 
}
```


### 3. Run the Script

```sh
go run client.go
```

### 4. View the Results

The output will be displayed in the terminal screen.

### 5. End


[**Watch the demo**] (https://nokia.sharepoint.com/:v:/r/sites/sr-linux-and-fss-npi-workshops/DCFabric-cNPI/Shared%20Documents/INTERNAL%20and%20Customer%20Demo%20recordings/Knowledge%20sharing%20sessions/EDA/eda-ws-client.mp4?csf=1&web=1&e=7Pkwod)