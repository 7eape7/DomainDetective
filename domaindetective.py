import os
import argparse
import configparser
import pandas
import dnstwist
from modules.settings import DATAFOLDER 
from modules.settings import CONFIGFOLDER
import modules.tf as tf
import modules.analyzeDomain as analyzeDomain

def display_domain_detective_menu():
    print("\nSelect an action:")
    print("1. Get domain permutations (registered)")
    print("2. Get domain permutations (unregistered)")
    print("3. Analyze registered domains")
    print("4. Exit")

def domain_detective_menu(targetDomain: str = None):
    while True:
        domains_file = f'{CONFIGFOLDER}/domains.txt'
        domains = []
        if targetDomain is not None:
            domains.append(targetDomain)
        else:
            if os.path.getsize(domains_file) == 0:
                domains.append(input("Target domain: "))
            else:
                try:
                    with open(domains_file, "r") as file:
                        for line in file:
                            domains.append(line.rstrip("\n"))
                except:
                    print("Error parsing domains.txt.\nEnsure domains are formatted properly or specify the '-domain' switch to run a single domain.")
        
        #Create Domain Analysis folder
        analysis_folder = f'{DATAFOLDER}/domain_analysis'
        try:
            os.mkdir(analysis_folder)
        except FileExistsError:
            pass
        print("\nAnalyzing the following domains:")
        for targetDomain in domains:
            print(targetDomain)
            try:
                os.mkdir(f"{analysis_folder}/{targetDomain}")
            except FileExistsError:
                pass
                #print(f"Using existing {targetDomain} folder for output.")
                
        display_domain_detective_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            for targetDomain in domains:
                print(f"Searching registered domain permutations for {targetDomain}. This may take a while...")
                output_path = f'{analysis_folder}/{targetDomain}/{targetDomain}_registered.csv'
                try:
                    dnstwist.run(domain=targetDomain, registered=True, format='csv', whois=True, output=output_path)
                except Exception as e:
                    if os.path.isfile(output_path):
                        delete_file = input("Domain permutations file already exists. Would you like to delete and run again? Y/N: ")
                        if delete_file == 'Y':
                            os.remove(output_path)
                            dnstwist.run(domain=targetDomain, registered=True, format='csv', whois=True, output=output_path)
                            pass
                        if delete_file == 'N':
                            continue
                        else:
                            continue
                    else:
                        print(e)
                        print(f"Failed to gather domain permutations.")
                        continue

                #Modify the saved CSV to add our needed columns
                custom_columns = ["Country", "Country Code", "Registered?", "Reputation"]
                csv = pandas.read_csv(f'{analysis_folder}/{targetDomain}/{targetDomain}_registered.csv')
                for column in custom_columns:
                    if column == "Registered?":
                        csv[column] = True
                    else:
                        csv[column] = None
                csv.to_csv(f'{analysis_folder}/{targetDomain}/{targetDomain}_registered.csv')
                print(f"Done! Output saved to {analysis_folder}/{targetDomain}/{targetDomain}_registered.csv")

        elif choice == '2':
            for targetDomain in domains:
                print(f"Searching unregistered domain permutations for {targetDomain}. This may take a while...")
                output_path = f'{analysis_folder}/{targetDomain}/{targetDomain}_unregistered.csv'
                try:
                    dnstwist.run(domain=targetDomain, registered=False, format='csv', whois=True, output=output_path)
                except Exception as e:
                    if os.path.isfile(output_path):
                        delete_file = input("Domain permutations file already exists. Would you like to delete and run again? Y/N: ")
                        if delete_file == 'Y':
                            os.remove(output_path)
                            dnstwist.run(domain=targetDomain, registered=False, format='csv', whois=True, output=output_path)
                            pass
                        if delete_file == 'N':
                            continue
                        else:
                            continue
                    else:
                        print(e)
                        print(f"Failed to gather domain permutations.")
                        continue
                
                #Modify the saved CSV to add our needed columns
                custom_columns = ["Country", "Country Code", "Registered?", "Reputation"]
                csv = pandas.read_csv(f'{analysis_folder}/{targetDomain}/{targetDomain}_unregistered.csv')
                for column in custom_columns:
                    if column == "Registered?":
                        csv[column] = False
                    else:
                        csv[column] = None
                csv.to_csv(f'{analysis_folder}/{targetDomain}/{targetDomain}_unregistered.csv')
                print(f"Done! Output saved to {analysis_folder}/{targetDomain}/{targetDomain}_unregistered.csv")

        elif choice == '3':
            print("NOTE: Reputation analysis results are NOT definitive. Conduct manual analysis to verify.")
            
            #Get API keys for external tools
            config = configparser.ConfigParser()
            config.read(f"{CONFIGFOLDER}/apikeys.conf")
            urlscanKey = config.get('urlscan', 'KEY')
            vtKey = config.get('virustotal', 'KEY')

            if not urlscanKey or not vtKey:
                print("Please configure API keys in apikeys.conf. Exiting.")
                exit()
            for targetDomain in domains:
                target_folder = f'{analysis_folder}/{targetDomain}'
                try:
                    os.mkdir(target_folder)
                except FileExistsError:
                    print(f"Domain analysis data will be saved to {target_folder}")
                
                #Check for registered targetDomain CSV - parse out the domain names
                csv_path = f'{analysis_folder}/{targetDomain}/{targetDomain}_registered.csv'
                if os.path.exists(csv_path):
                    csv = pandas.read_csv(csv_path)
                    domains = csv["domain"]
                else:
                    print(f"List of {targetDomain} permutations has not been generated. Please generate before analysis.")
                    continue

                #Run reputation for each registered domain and save to their own subfolders in the Domain Analysis folder
                for domain_name in domains:
                    domain = analyzeDomain.Domain(domain_name, urlscanKey, vtKey, outputPath=f'{target_folder}')
                    domain.analyze()
                    columns = {
                        "Country": "country",
                        "Country Code": "cc",
                        "Reputation": "reputation"
                    }
                    for key in columns:
                        try:
                            item = getattr(domain, columns[key])
                            csv.loc[csv["domain"] == domain_name, key] = item
                        except AttributeError:
                            print("Attribute error")
                            continue
                csv.to_csv(f'{analysis_folder}/{targetDomain}/{targetDomain}_registered.csv')
                print(f"Done! Updated {analysis_folder}/{targetDomain}/{targetDomain}_registered.csv with domain analysis data.")

        elif choice == '4':
            print("Exiting...\n")
            break
        else:
            tf.tableflip()
            print("Invalid choice. Please try again.\n")

def main():
    parser = argparse.ArgumentParser(prog="DomainDetective",
                                    usage="domaindetective.py [options]", epilog="EXAMPLE: domaindetective.py -targetDomain google.com")
    parser.add_argument('-targetDomain', type=str, help="Single domain to target.")
    args = parser.parse_args()

    if args.targetDomain:
        domain_detective_menu(args.targetDomain)
    else:
        domain_detective_menu()

if __name__ == "__main__":
    main()