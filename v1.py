import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
from PIL import Image, ImageTk

class SubdomainFinderGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Subdomain Finder GUI")
        self.geometry("800x600")

        # Set background image
        self.background_image = Image.open("background_image.png")
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(self, image=self.background_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.create_widgets()

    def create_widgets(self):
        # Domain entry
        domain_frame = tk.Frame(self, bg="white")
        domain_frame.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
        tk.Label(domain_frame, text="Domain:").grid(row=0, column=0, padx=10, pady=10)
        self.domain_entry = tk.Entry(domain_frame)
        self.domain_entry.grid(row=0, column=1, padx=10, pady=10)

        # Run button
        self.run_button = tk.Button(self, text="Find Subdomains", command=self.find_subdomains)
        self.run_button.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

        # Output text area
        self.output_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=90, height=30, bg="white", relief="flat")
        self.output_text.place(relx=0.5, rely=0.65, anchor=tk.CENTER)

    def find_subdomains(self):
        domain = self.domain_entry.get()
        if not domain:
            messagebox.showerror("Error", "Domain is required")
            return

        # Clear previous output
        self.output_text.delete(1.0, tk.END)

        # Check if the domain is reachable
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            if response.status_code != 200:
                messagebox.showerror("Error", f"Domain is not reachable (HTTP {response.status_code})")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Error checking domain: {str(e)}")
            return

        self.output_text.insert(tk.END, f"Finding subdomains for: {domain}\n\n")

        subdomains = set()

        # Collect subdomains from different sources
        subdomains.update(self.search_crtsh(domain))
        subdomains.update(self.search_threatcrowd(domain))
        subdomains.update(self.search_dnsdumpster(domain))
        subdomains.update(self.search_sublist3r(domain))

        if subdomains:
            self.output_text.insert(tk.END, "Found subdomains:\n")
            for subdomain in sorted(subdomains):
                self.output_text.insert(tk.END, f"{subdomain}\n")
        else:
            self.output_text.insert(tk.END, "No subdomains found.\n")

    def search_crtsh(self, domain):
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if entry['name_value'].startswith("*."):  # Filter out wildcard subdomains
                        continue
                    subdomains.add(entry['name_value'])
        except Exception as e:
            self.output_text.insert(tk.END, f"Error querying crt.sh: {str(e)}\n")
        return subdomains

    def search_threatcrowd(self, domain):
        subdomains = set()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    subdomains.update(data['subdomains'])
        except Exception as e:
            self.output_text.insert(tk.END, f"Error querying ThreatCrowd: {str(e)}\n")
        return subdomains

    def search_dnsdumpster(self, domain):
        subdomains = set()
        url = f"https://api.dnsdumpster.com/?q={domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                 data = response.json()
                 if 'dns_records' in data:
                    subdomains.add(record['domain'])
        except Exception as e:
            self.output_text.insert(tk.END, f"Error querying DNSDumpster: {str(e)}\n")
        return subdomains

    def search_sublist3r(self, domain):
        subdomains = set()
        url = f"https://api.sublist3r.com/search.php?domain={domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                subdomains.update(data['subdomains'])
        except Exception as e:
            self.output_text.insert(tk.END, f"Error querying Sublist3r: {str(e)}\n")
        return subdomains


if __name__ == "__main__":
    app = SubdomainFinderGUI()
    app.mainloop()
