#UPDATE LINE 233 where you stored the logo file you want to use!!!!

# -*- coding: utf-8 -*-
"""
Copyright (c) 2024 - Harry Shelton
All rights reserved.

This project is licensed under the MIT License. You may obtain a copy of the License at
https://opensource.org/licenses/MIT

You are free to use, modify, and distribute this software under the terms of the MIT License.
This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the MIT License for more details.

Author: Harry Shelton
Date: 6th September 2024
Repository: https://github.com/itsharryshelton/BulkPortScanner

Bulk Port Scanner - Version 1.0.3
"""

from customtkinter import *
import csv
import nmap
import time
import threading
from tkinter import filedialog
import subprocess
import os

scanning = False  # Global flag to control the scanning process
output_file_path = None  # Global variable to store the output file path

def read_customers_from_csv(file_path):
    customer_list = []
    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            customer_list.append({'customer_name': row['customer_name'], 'ip': row['ip']})
    return customer_list

def scan_ip(ip, nm, ports=None):
    try:
        if ports:
            nm.scan(ip, arguments=f'-p {ports}')
        else:
            nm.scan(ip, arguments='--top-ports 100')
        return nm[ip]
    except Exception as e:
        return None

def scan_ports_all(ip, nm):
    try:
        nm.scan(ip, arguments='-p-')  # Scan all ports
        return nm[ip]
    except Exception as e:
        return None

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
    return filedialog.askopenfilename(
        title="Select the input CSV file",
        filetypes=[("CSV files", "*.csv")],
        defaultextension=".csv"
    )

def get_output_file_path():
    global output_file_path
    if not output_file_path:  # If the output file path is not set
        output_file_path = filedialog.asksaveasfilename(
            title="Save the output CSV file",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
    return output_file_path

def update_gui_log(text_widget, message):
    text_widget.configure(state="normal")
    text_widget.insert(END, message + "\n")
    text_widget.see(END)
    text_widget.configure(state="disabled")

def scan_and_log_process(input_file, text_widget, ports=None):
    global scanning
    nm = nmap.PortScanner()
    customer_list = read_customers_from_csv(input_file)
    scan_results = []

    for customer in customer_list:
        if not scanning:
            break  # If scanning flag is turned off, stop the scan

        customer_name = customer['customer_name']
        ip = customer['ip']
        update_gui_log(text_widget, f"Scanning IP: {ip} for customer: {customer_name}")
        
        scan_data = scan_ip(ip, nm, ports)
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

    export_results_to_csv(scan_results, output_file_path)
    update_gui_log(text_widget, f"Scan results saved to {output_file_path}")

def scan_all_ports_process(input_file, text_widget):
    global scanning
    nm = nmap.PortScanner()
    customer_list = read_customers_from_csv(input_file)
    scan_results = []

    for customer in customer_list:
        if not scanning:
            break  # If scanning flag is turned off, stop the scan

        customer_name = customer['customer_name']
        ip = customer['ip']
        update_gui_log(text_widget, f"Scanning all ports on IP: {ip} for customer: {customer_name}")
        
        scan_data = scan_ports_all(ip, nm)
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

    export_results_to_csv(scan_results, output_file_path)
    update_gui_log(text_widget, f"All port scan results saved to {output_file_path}")

def start_scan(input_file, text_widget, ports=None):
    global scanning
    if not get_output_file_path():
        update_gui_log(text_widget, "No output file path selected. Exiting.")
        return
    
    scanning = True  # Set the scanning flag to True
    update_gui_log(text_widget, "Starting scan...")
    threading.Thread(target=scan_and_log_process, args=(input_file, text_widget, ports)).start()

def stop_scan(text_widget):
    global scanning
    scanning = False  # Set the scanning flag to False to stop the scan
    update_gui_log(text_widget, "Stopping scan...")

def scan_selected_ports(input_file, text_widget, ports_entry):
    ports = ports_entry.get()
    if not ports:
        update_gui_log(text_widget, "No ports entered. Exiting.")
        return
    start_scan(input_file, text_widget, ports)

def scan_all_ports(input_file, text_widget):
    start_scan(input_file, text_widget)  # Default to scanning all ports

def review_results(text_widget):
    global output_file_path
    if not output_file_path or not os.path.exists(output_file_path):
        output_file_path = filedialog.askopenfilename(
            title="Select the CSV file to review",
            filetypes=[("CSV files", "*.csv")],
            defaultextension=".csv"
        )
        if not output_file_path:
            update_gui_log(text_widget, "No file selected. Exiting review.")
            return

    # Suppress the command prompt window on Windows
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    process = subprocess.Popen(
        ["python", "review_results.py", output_file_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        startupinfo=startupinfo
    )

    stdout, stderr = process.communicate()
    if process.returncode != 0:
        update_gui_log(text_widget, f"Error running review script: {stderr.decode()}")
    else:
        update_gui_log(text_widget, "Review script completed successfully.")
        
def main():
    global output_file_path
    set_appearance_mode("System")
    set_default_color_theme("blue")

    root = CTk()
    root.title("Bulk Port Scanner")
    root.geometry("600x400")
    root.iconbitmap('logo.ico')

    frame = CTkFrame(root, fg_color=root.cget('bg'))
    frame.pack(pady=10, padx=20, fill="both", expand=True)

    text_widget = CTkTextbox(frame, wrap="word", width=550, height=150, state="disabled")
    text_widget.pack(padx=10, pady=(5, 5))

    input_frame = CTkFrame(frame, fg_color=root.cget('bg'))
    input_frame.pack(pady=5, fill="x", expand=True)

    ports_entry = CTkEntry(input_frame, placeholder_text="Enter ports (e.g., 22,80,443 or 1-1000)")
    ports_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)

    scan_ports_button = CTkButton(input_frame, text="Scan Selected Ports", command=lambda: scan_selected_ports(get_csv_file_path(), text_widget, ports_entry))
    scan_ports_button.pack(side="left", padx=5, pady=5)

    control_frame = CTkFrame(frame, fg_color=root.cget('bg'))
    control_frame.pack(pady=5, fill="x", expand=True)

    start_button_frame = CTkFrame(control_frame, fg_color=root.cget('bg'))
    start_button_frame.pack(side="left", padx=5, pady=5)

    start_button = CTkButton(start_button_frame, text="Scan Top 100 Ports", command=lambda: start_scan(get_csv_file_path(), text_widget))
    start_button.pack(side="left", padx=5)

    scan_all_ports_button = CTkButton(control_frame, text="Scan All Ports", command=lambda: scan_all_ports(get_csv_file_path(), text_widget))
    scan_all_ports_button.pack(side="left", padx=5)

    stop_button = CTkButton(control_frame, text="Stop Scan", command=lambda: stop_scan(text_widget))
    stop_button.pack(side="left", padx=5)

    review_results_button = CTkButton(frame, text="Review Results", command=lambda: review_results(text_widget))
    review_results_button.pack(side="left",pady=5,padx=10)

    footer_frame = CTkFrame(root, fg_color=root.cget('bg'))
    footer_frame.pack(side="bottom", fill="x", pady=10)

    footer_label = CTkLabel(footer_frame, text="Copyright (c) 2024 - Harry Shelton | Version 1.0.3", anchor="e")
    footer_label.pack(side="right", padx=10)

    root.mainloop()

if __name__ == "__main__":
    main()
