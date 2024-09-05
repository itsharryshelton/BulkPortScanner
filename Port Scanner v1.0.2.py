#UPDATE LINE 125 where you stored the logo file you want to use!!!!

from customtkinter import *
import csv
import nmap
import time
import threading
from tkinter import filedialog

scanning = False  #Global flag to control the scanning process

#Read the input CSV function
def read_customers_from_csv(file_path):
    customer_list = []
    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            customer_list.append({'customer_name': row['customer_name'], 'ip': row['ip']})
    return customer_list

#Scanning Function
def scan_ip(ip, nm):
    try:
        nm.scan(ip, arguments='--top-ports 100')
        return nm[ip]
    except Exception as e:
        return None

#Export to CSV with details
def export_results_to_csv(scan_results, output_file):
    with open(output_file, mode='w', newline='') as file:
        fieldnames = ['customer_name', 'ip', 'port', 'state', 'name', 'product', 'version']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        
        for customer_name, ip, port_data in scan_results:
            for port in port_data:
                writer.writerow({
                    'customer_name': customer_name,
                    'ip': ip,
                    'port': port['port'],
                    'state': port['state'],
                    'name': port.get('name', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', '')
                })

def get_csv_file_path():
    file_path = filedialog.askopenfilename(
        title="Select the input CSV file",
        filetypes=[("CSV files", "*.csv")],
        defaultextension=".csv"
    )
    return file_path

def get_output_file_path():
    output_file = filedialog.asksaveasfilename(
        title="Save the output CSV file",
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")]
    )
    return output_file

def update_gui_log(text_widget, message):
    text_widget.configure(state="normal")
    text_widget.insert(END, message + "\n")
    text_widget.see(END)
    text_widget.configure(state="disabled")

def scan_and_log_process(input_file, output_file, text_widget):
    global scanning
    nm = nmap.PortScanner()
    customer_list = read_customers_from_csv(input_file)
    scan_results = []

    for customer in customer_list:
        if not scanning:
            break  #If scanning flag is turned off, stop the scan

        customer_name = customer['customer_name']
        ip = customer['ip']
        update_gui_log(text_widget, f"Scanning IP: {ip} for customer: {customer_name}")
        
        scan_data = scan_ip(ip, nm)
        if scan_data:
            port_data = []
            for proto in scan_data.all_protocols():
                ports = scan_data[proto].keys()
                for port in ports:
                    port_data.append({
                        'port': port,
                        'state': scan_data[proto][port]['state'],
                        'name': scan_data[proto][port].get('name', ''),
                        'product': scan_data[proto][port].get('product', ''),
                        'version': scan_data[proto][port].get('version', '')
                    })
            scan_results.append((customer_name, ip, port_data))
        else:
            update_gui_log(text_widget, f"Failed to scan IP: {ip}")
        time.sleep(1)

    export_results_to_csv(scan_results, output_file)
    update_gui_log(text_widget, f"Scan results saved to {output_file}")

#Functions for the buttons
def start_scan(input_file, output_file, text_widget):
    global scanning
    scanning = True
    update_gui_log(text_widget, "Starting scan...")
    threading.Thread(target=scan_and_log_process, args=(input_file, output_file, text_widget)).start()

def stop_scan(text_widget):
    global scanning
    scanning = False
    update_gui_log(text_widget, "Stopping scan...")

#Main Function for GUI & Starting Scan
def main():
    set_appearance_mode("Dark")  
    set_default_color_theme("blue")

    root = CTk()  #GUI Box Starts Here
    root.title("Port Scanner")
    root.geometry("600x400")
    root.iconbitmap('logo.ico') #UPDATE ME!!! I need to be the correct path for the logo!!!!!!!!!!

    frame = CTkFrame(root)
    frame.pack(pady=20, padx=20, fill="both", expand=True)

    text_widget = CTkTextbox(frame, wrap="word", width=550, height=250, state="disabled")
    text_widget.pack(padx=10, pady=10)

    def on_start():
        input_file = get_csv_file_path()
        if not input_file:
            update_gui_log(text_widget, "No input file selected. Exiting.")
            return

        output_file = get_output_file_path()
        if not output_file:
            update_gui_log(text_widget, "No output file selected. Exiting.")
            return

        start_scan(input_file, output_file, text_widget)

    start_button = CTkButton(frame, text="Start Scan", command=on_start)
    start_button.pack(side="left", padx=10, pady=10)

    stop_button = CTkButton(frame, text="Stop Scan", command=lambda: stop_scan(text_widget))
    stop_button.pack(side="left", padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
