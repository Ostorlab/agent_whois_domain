<h1 align="center">Agent Whois</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_whois_domain">
<img src="https://img.shields.io/github/stars/ostorlab/agent_whois_domain">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Agent responsible for retrieving WHOIS information of a domain such as it's name servers, contact information, registrar, and address._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_whois_domain/blob/main/images/logo.png" alt="agent-whois-domain" />
</p>

This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for [python-whois](https://pypi.org/project/python-whois/).

## Getting Started
To perform your first scan, simply run the following command.
```shell
oxo scan run --install --agent agent/ostorlab/whois_domain domain-name tesla.com
```

This command will download and install `agent/ostorlab/whois_domain`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Whois can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/whois_domain
 ```

You can then run the agent with the following command:

```shell
oxo scan run --agent agent/ostorlab/whois_domain domain-name tesla.com
```


### Build directly from the repository

 1. To build the whois_domain agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_whois_domain.git && cd agent_whois_domain
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 1. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  oxo scan run --agent agent//whois_domain domain-name tesla.com
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  oxo scan run --agent agent/[ORGANIZATION]/whois_domain domain-name tesla.com
	  ```

## License
[Apache-2](./LICENSE)
