# Netnoot: Asus Firewall analytics server

## Introduction
Netnoot is a powerful tool designed to receive logs from your Asus firewall and analyze dropped packets, providing detailed reports on potential security threats and attack vectors. The service is built as a lightweight server application that runs seamlessly within a Docker container, ensuring ease of deployment and management. The primary goal of this project is to enhance personal cybersecurity by offering insights into possible attack vectors and improving overall cyber resilience.

## Features

- Real-time Log Analysis: Netnoot continuously monitors incoming logs from your Asus firewall, analyzing dropped packets in real-time to detect suspicious activity.
- Comprehensive Reporting: Generates detailed reports on potential threats, including the source of the attack, type of threat, and frequency of attempts.
- Lightweight and Efficient: Designed to be a low-footprint application that can run efficiently in a Docker container on any compatible system.
- Easy to Deploy: With Docker support, you can quickly set up and run Netnoot without complex installation processes.
- Historical Data Analysis: Maintains a history of log data for trend analysis and long-term monitoring of your network's security posture.


## Examples

Here are a few examples of how Netnoot can help improve your network's security:
- Detecting Port Scanning Attempts: Identify and block IP addresses that are repeatedly attempting to scan your network for open ports.
- Monitoring for DDoS Attacks: Receive alerts when the system detects patterns indicative of a Distributed Denial-of-Service attack.
- Identifying Malicious IPs: Automatically cross-reference incoming threats with a known list of malicious IP addresses.


## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed on your system:
  - Docker
  - Asus router with packet drop logging enabled
  - A system to deploy the Netnoot Docker container

### Installation

1. Clone the Repo
```zsh
git clone https://Madmegsox1/netnoot.git
cd netnoot
```
2. Build the docker image
```zsh
docker build -t netnoot --build-arg port={PORT} .
```
3. docker run 
```zsh
docker run -d --name netnoot-server -p {PORT}:{PORT}/udp netnoot
```
The server will now be running and listening for incoming log data on the port that you have set.

You can see if it is working by checking the docker containers logs like this
```zsh
docker logs netnoot-server
```

## Contributing
Contributions are welcome! If you'd like to help improve Netnoot, please fork the repository and create a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

## License
Netnoot is released under the MIT License. See LICENSE for more information.

## Support
If you have any questions or need help, please open an issue on the GitHub repository.
