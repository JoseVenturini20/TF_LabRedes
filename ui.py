import tkinter as tk
from tkinter import ttk
import threading
import queue
<<<<<<< HEAD
from sniffer import check_arp_counts, check_icmp_counts, clear_icmp_and_arp_tables, create_raw_socket, receive_pkg
packets_queue = queue.Queue()
columns = ('ip_version', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'tcp_flags', 'protocol_type', 'ARP_and_ICMP_info')
suspected_attack_location = None
def sniffer_thread():
    receive_pkg(packets_queue)  # Modified sniffer function that accepts a queue
# Start the sniffer in a separate thread
=======

from sniffer import receive_pkg

packets_queue = queue.Queue()

columns = ('ip_version', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'tcp_flags')
suspected_attack_location = None  


def sniffer_thread():
    receive_pkg(packets_queue)  # Modified sniffer function that accepts a queue

# Start the sniffer in a separate thread
sniffer_thread = threading.Thread(target=sniffer_thread, daemon=True)
sniffer_thread.start()
>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e

def packet_capture_simulation():
    import random
    import time
    while True:
        time.sleep(random.uniform(0.1, 0.2))
        packet_data = {
            'ip_version': 'IPv4',
            'src_mac': f'{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}',
            'dst_mac': f'{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}',
            'src_ip': f'192.168.0.{random.randint(1,255)}',
            'dst_ip': f'192.168.0.{random.randint(1,255)}',
            'src_port': random.randint(1024, 65535),
            'dst_port': random.randint(1024, 65535),
<<<<<<< HEAD
            'tcp_flags': random.randint(0, 255),
        }
        packets_queue.put(packet_data)
=======
            'tcp_flags': random.randint(0, 255)
        }
        packets_queue.put(packet_data)

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
def detect_attacks(packet_data):
    attacks_detected = {
        'ARP Spoofing': False,
        'ICMP Flooding': False
    }
<<<<<<< HEAD
    if check_arp_counts():
        attacks_detected['ARP Spoofing'] = True
    if check_icmp_counts():
        attacks_detected['ICMP Flooding'] = True
    return attacks_detected
def update_attack_info(attacks_detected, attack_info_label):
    text = "\n".join(f"{attack}: {'Detected!' if status else 'Not Detected'}" for attack, status in attacks_detected.items())
    attack_info_label.config(text=text)
=======

    if False:
        attacks_detected['ARP Spoofing'] = True

    if False:
        attacks_detected['ICMP Flooding'] = True

    return attacks_detected

def update_attack_info(attacks_detected, attack_info_label):
    text = "\n".join(f"{attack}: {'Detected!' if status else 'Not Detected'}" for attack, status in attacks_detected.items())
    attack_info_label.config(text=text)

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
    if any(attacks_detected.values()):
        attack_info_label.config(bg='red')
    else:
        attack_info_label.config(bg='green')
<<<<<<< HEAD
=======

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
def update_treeview(tree, queue, attack_info_label):
    while True:
        if not queue.empty():
            packet = queue.get()
            tree.insert('', 'end', values=list(packet.values()))
            attacks_detected = detect_attacks(packet)
            update_attack_info(attacks_detected, attack_info_label)
<<<<<<< HEAD
def search_in_treeview(tree, search_query, search_result_label):
    matching_items = []
    search_query = search_query.lower()
    for child in tree.get_children():
        if search_query in str(tree.item(child)['values']).lower():
            matching_items.append(child)
    search_result_label.config(text=f'{len(matching_items)} Matches found')
    return matching_items
def navigate_results(tree, matching_items, direction, current_index, index_label):
    if matching_items:
        current_index[0] = (current_index[0] + direction) % len(matching_items)
        selected_item = matching_items[current_index[0]]
        tree.selection_set(selected_item)
        tree.see(selected_item)
        index_label.config(text=f'Index: {current_index[0]+1}/{len(matching_items)}')
def setup_gui():
    root = tk.Tk()
    root.title("Network Packet Sniffer")
=======

def search_in_treeview(tree, search_query, search_result_label):
    matching_items = []

    search_query = search_query.lower()

    for child in tree.get_children():
        if search_query in str(tree.item(child)['values']).lower():
            matching_items.append(child)

    search_result_label.config(text=f'{len(matching_items)} Matches found')

    return matching_items

def navigate_results(tree, matching_items, direction, current_index, index_label):
    if matching_items:
        current_index[0] = (current_index[0] + direction) % len(matching_items)
        
        selected_item = matching_items[current_index[0]]
        tree.selection_set(selected_item)
        tree.see(selected_item)
        
        index_label.config(text=f'Index: {current_index[0]+1}/{len(matching_items)}')

def setup_gui():
    root = tk.Tk()
    root.title("Network Packet Sniffer")

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
    tree_frame = ttk.Frame(root)
    tree_frame.pack(side='top', fill='both', expand=True)
    search_frame = ttk.Frame(root)
    search_frame.pack(side='top', fill='x')
<<<<<<< HEAD
    search_entry = tk.Entry(search_frame)
    search_entry.pack(side='left', fill='x', expand=True, padx=10, pady=5)
    search_button = ttk.Button(search_frame, text='Search', command=lambda: search_in_treeview(tree, search_entry.get()))
    search_button.pack(side='right', padx=10, pady=5)
    search_result_label = tk.Label(search_frame, text='0 Matches found')
    search_result_label.pack(side='left', padx=10)
    matching_items = []
    current_index = [0]
    index_label = tk.Label(search_frame, text='Index: 0/0')
    index_label.pack(side='left')
=======

    search_entry = tk.Entry(search_frame)
    search_entry.pack(side='left', fill='x', expand=True, padx=10, pady=5)

    search_button = ttk.Button(search_frame, text='Search', command=lambda: search_in_treeview(tree, search_entry.get()))
    search_button.pack(side='right', padx=10, pady=5)

    search_result_label = tk.Label(search_frame, text='0 Matches found')
    search_result_label.pack(side='left', padx=10)

    matching_items = []
    current_index = [0] 
    index_label = tk.Label(search_frame, text='Index: 0/0')
    index_label.pack(side='left')

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
    prev_button = ttk.Button(search_frame, text='Previous', command=lambda: navigate_results(tree, matching_items, -1, current_index, index_label))
    prev_button.pack(side='left', padx=5)
    next_button = ttk.Button(search_frame, text='Next', command=lambda: navigate_results(tree, matching_items, 1, current_index, index_label))
    next_button.pack(side='left', padx=5)
<<<<<<< HEAD
    search_button.config(command=lambda: matching_items.clear() or matching_items.extend(search_in_treeview(tree, search_entry.get(), search_result_label)))
=======

    search_button.config(command=lambda: matching_items.clear() or matching_items.extend(search_in_treeview(tree, search_entry.get(), search_result_label)))

>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
    attack_info_frame = ttk.Frame(tree_frame, width=200)
    attack_info_frame.pack(side='right', fill='y', expand=False)
    attack_info_label = tk.Label(attack_info_frame, text='No Attacks Detected', bg='green', fg='white', justify=tk.LEFT)
    attack_info_label.pack(fill='both', expand=True)
<<<<<<< HEAD
    tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
    for col in columns:
        if col == 'ARP_and_ICMP_info':
            tree.heading(col, text='ARP and ICMP info')
            tree.column(col, width=300, anchor='center')
        # elif col == 'tcp_flags' or col == 'protocol_type' or col == 'ip_version':
        #     tree.heading(col, text=col.title().replace('_', ' '), option=)
        #     tree.column(col, width=50, anchor='center')
        else:
            tree.heading(col, text=col.title().replace('_', ' '))
            tree.column(col, width=100, anchor='center')
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    vsb.pack(side='right', fill='y')
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side='left', fill='both', expand=True)
    socket = create_raw_socket()
    sniffer_thread = threading.Thread(target=receive_pkg, args=(socket, packets_queue), daemon=True)
    timer = threading.Thread(target=clear_icmp_and_arp_tables)
    timer.start()
    sniffer_thread.start()
    update_thread = threading.Thread(target=update_treeview, args=(tree, packets_queue, attack_info_label), daemon=True)
    update_thread.start()
    root.mainloop()
=======

    tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
    for col in columns:
        tree.heading(col, text=col.title().replace('_', ' '))
        tree.column(col, width=100, anchor='center') 

    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    vsb.pack(side='right', fill='y')
    tree.configure(yscrollcommand=vsb.set)

    tree.pack(side='left', fill='both', expand=True)

    update_thread = threading.Thread(target=update_treeview, args=(tree, packets_queue, attack_info_label), daemon=True)
    update_thread.start()

    root.mainloop()


>>>>>>> f8d2aeff0f1f2e7c35033dfb81d182f731571b0e
if __name__ == "__main__":
    setup_gui()