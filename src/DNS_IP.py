import csv
import dns.resolver


# Path to your CSV file

CSV_FILE_PATH = "src/Source_Data/Cloudflare_Top100_Domains.csv"
OUTPUT_FILE_PATH = "src/Source_Data/Domain_Robustness_Results.csv"
def check_domain_robustness(domain):
    """Resolves A and AAAA records for a domain and returns its robustness classification."""
    has_ipv4 = False
    has_ipv6 = False

    print(f"\n--- Checking DNS for: {domain} ---")

    # 1. Lookup IPv4 (A Records)
    try:
        # Searched for the IPv4 records, handles exceptions not as errors, but just as not found. 
        ipv4_records = dns.resolver.resolve(domain, 'A')
        for ip in ipv4_records:
            print(f"  IPv4 Address: {ip.to_text()}")
        has_ipv4 = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print("  IPv4 address not found")
    except Exception as e:
        print(f"  Error fetching IPv4: {e}")

    # 2. Lookup IPv6 (AAAA Records)
    try:
        # Searched for the IPv4 records, handles exceptions not as errors, but just as not found. 
        ipv6_records = dns.resolver.resolve(domain, 'AAAA')
        for ip in ipv6_records:
            print(f"  IPv6 Address: {ip.to_text()}")
        has_ipv6 = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print("  IPv6 address not found")
    except Exception as e:
        print(f"  Error fetching IPv6: {e}")

    # 3. Classify Robustness
    # Has high robustness if has both IPv4 and IPv6 addresses. 
    if has_ipv4 and has_ipv6:
        classification = "High Robustness"
    # Has low robustness if has IPv4 or IPv6
    elif has_ipv4:
        classification = "Old robustness - low"
    elif has_ipv6:
        classification = "New robustness - low"
    # If they don't have any of the two, it classifies it as 'dead'
    else:
        classification = "No IP Support (Dead/Parked)"

    print(f"  Result: {classification}")
    # Returns Classification to store it. 
    return classification



def obtain_domain_IP():
    """
    Opens the Cloudflare domains file, checks each domain's IP robustness,
    and saves the consolidated results matrix to a new CSV file.
    """
    rows_to_save = []

    # --- Step 1: Read and Analyze Input Data ---
    try:
        with open(CSV_FILE_PATH, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            
            # Skip header row
            try:
                next(csv_reader) 
            except StopIteration:
                print("Error: The source CSV file is empty.")
                return
            
            for row in csv_reader:
                if not row or len(row) <= 1:
                    continue
                    
                # Take the domain from the second column (index 1)
                domain = row[1].strip()
                
                # Execute evaluation and capture the returned classification string
                classification = check_domain_robustness(domain)
                
                # Append data to our tracking list
                rows_to_save.append({
                    "domain": domain,
                    "robustness_classification": classification
                })
                
    except FileNotFoundError:
        print(f"Error: The source file '{CSV_FILE_PATH}' was not found. Please check the path.")
        return  # Exit early if input file doesn't exist

    # --- Step 2: Write Results to Output CSV ---
    print(f"\n[#] Analysis Complete. Exporting records to: {OUTPUT_FILE_PATH}")
    try:
        fieldnames = ["domain", "robustness_classification"]
        with open(OUTPUT_FILE_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows_to_save)
        print(f"[✓] Successfully wrote {len(rows_to_save)} rows to the output file.")
    except IOError as e:
        print(f"[✗] File writing error: Could not save results to file. {e}")


if __name__ == "__main__":
    obtain_domain_IP()
