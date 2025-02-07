<!-- ABOUT THE PROJECT -->
## DomainDetective

DomainDetective uses OSINT to find interesting data about domains. 

<!-- GETTING STARTED -->
### Prerequisites

Clone the repository and install the required python libraries then you should be good to go!
  ```sh
  pip3 install -r requirements.txt
  ```

Insert applicable API keys in apikeys.conf. Currently only setup for URLScan.io with plans for VirusTotal and beyond.

<!-- USAGE EXAMPLES -->
## Usage

DomainDetective can be executed from the command line with no arguments specified or you may choose to specify a single target domain:
  ```sh
  domaindetective.py -targetDomain google.com
  ```

When executed with no arguments, it will first look at the data/domains.txt file for any domains entered (you may analyze multiple domains at once). If the file doesn't exist or contains no data it will prompt you for a domain to target.

Once executed and a domain(s) are input for analysis, choose from the menu of options to get started. 
  ```sh
  Analyzing the following domains:
  google.com

  Select an action:
  1. Get domain permutations (registered)
  2. Get domain permutations (unregistered)
  3. Analyze registered domains
  4. Exit
  Enter your choice: 
  ```

Data is output to the data/domain_analysis folder, including CSVs, screenshots, etc.

<!-- ROADMAP -->
## Roadmap

- [ ] VirusTotal API functions
- [ ] Subdomain enumeration and screenshot functions

<!-- LICENSE -->
## License

Distributed under the MIT license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>