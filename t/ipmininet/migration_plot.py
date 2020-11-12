import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import argparse

parser = argparse.ArgumentParser(description="Simple plot for the mig experiment")
parser.add_argument("--path_v4")
parser.add_argument("--path_v6")

def parse_file(pathfile):
    all_bws = []
    with open(pathfile) as f:
        for line in f:
            eth, bw = line.split()
            all_bws.append(float(bw)/1024)
    return all_bws

if __name__ == "__main__":
    args = parser.parse_args()

    bw_v4 = parse_file(args.path_v4)
    bw_v6 = parse_file(args.path_v6)
    
    t = np.arange(0, len(bw_v4), 1)
    
    fig, ax = plt.subplots()
    ax.plot(t, bw_v4, label="v4")
    ax.plot(t, bw_v6, label="v6")

    ax.set(xlabel='time (s)', ylabel="Bandwidth (KiB/s)",
           title="Application-level TCPLS connection migration")
    ax.legend()
    fig.savefig("migration.png")
    plt.show()

