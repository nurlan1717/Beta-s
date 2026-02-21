import os
import time
import math
import collections
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# --- CONFIGURATION ---
TARGET_DIR = "target_data"
REFRESH_INTERVAL_MS = 1000
# ---------------------

def calculate_shannon_entropy(data):
    """Calculates Shannon Entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0
    
    entropy = 0
    counter = collections.Counter(data)
    length = len(data)
    
    for count in counter.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    
    return entropy

def get_folder_entropy():
    """
    Scans the specific folder and returns the average entropy of files.
    """
    if not os.path.exists(TARGET_DIR):
        print(f"[-] Waiting for directory {TARGET_DIR}...")
        return 0
        
    entropies = []
    
    try:
        for filename in os.listdir(TARGET_DIR):
            filepath = os.path.join(TARGET_DIR, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "rb") as f:
                        data = f.read(1024 * 64) # Read first 64KB for speed
                    e = calculate_shannon_entropy(data)
                    entropies.append(e)
                except:
                    pass
    except Exception as e:
        print(e)
        
    if not entropies:
        return 0
    return sum(entropies) / len(entropies)

# Global lists for plotting
x_vals = []
y_vals = []
start_time = time.time()

def animate(i):
    current_time = time.time() - start_time
    avg_entropy = get_folder_entropy()
    
    x_vals.append(current_time)
    y_vals.append(avg_entropy)
    
    # Keep window moving
    if len(x_vals) > 50:
        x_vals.pop(0)
        y_vals.pop(0)
        
    plt.cla() # Clear axis
    
    # Color logic: Green = Safe, Red = Encryption Detected
    color = 'green'
    if avg_entropy > 7.0:
        color = 'red'
        plt.text(current_time, avg_entropy, "⚠️ RANSOMWARE DETECTED!", fontsize=12, color='red', fontweight='bold')
    
    plt.plot(x_vals, y_vals, color=color, linewidth=2, marker='o')
    
    plt.title(f"Real-Time Entropy Analysis (Shannon)")
    plt.ylabel("Average Entropy (Bits)")
    plt.xlabel("Time (s)")
    plt.ylim(0, 8.5) # Shannon entropy max is 8
    plt.axhline(y=7.5, color='r', linestyle='--', label="Encryption Threshold")
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend(loc='lower right')
    plt.tight_layout()

def main():
    print("=== BLUE TEAM: ENTROPY MONITOR ===")
    print("[*] Monitoring folder for High Entropy (Encryption)...")
    print("[*] Graph will open in a new window.")
    
    # Create the graph
    plt.style.use('dark_background')
    ani = FuncAnimation(plt.gcf(), animate, interval=REFRESH_INTERVAL_MS)
    plt.show()

if __name__ == "__main__":
    main()
