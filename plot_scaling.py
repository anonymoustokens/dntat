#!/usr/bin/env python3
"""
Plot execution times for issuance and verification of MPC NTAT and BM NTAT
as the number of signers increases (log-log scale).
Includes simulated network communication latency.

Communication model:
  - MPC NTAT ring protocol: n sequential rounds (each round = 1 hop latency)
    + 2 broadcast rounds (client→signers, signers→client) for verify/response phases
  - BM NTAT: 2 broadcast rounds (client→signers, signers→client)
"""

import csv
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Simulated per-hop network latency (ms)
# 0.016 ms ≈ 16 μs, typical LAN latency
LATENCY_MS = 0.016

def read_csv(filename):
    path = os.path.join(SCRIPT_DIR, filename)
    n_vals, sign_vals, verify_vals = [], [], []
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            n_vals.append(int(row['n']))
            sign_vals.append(float(row['sign_ms']))
            verify_vals.append(float(row['verify_ms']))
    return n_vals, sign_vals, verify_vals

# Read data
mpc_n, mpc_sign_comp, mpc_verify = read_csv('mpcntat_scaling.csv')
bm_n, bm_sign_comp, bm_verify = read_csv('bmntat_scaling.csv')

# Add communication latency
# MPC: 2 broadcast rounds (client↔signers) + n rounds for ring MPC secure sum
mpc_sign_total = [comp + (2 + n) * LATENCY_MS for comp, n in zip(mpc_sign_comp, mpc_n)]
# BM: 2 broadcast rounds (client↔signers), no sequential rounds
bm_sign_total = [comp + 2 * LATENCY_MS for comp in bm_sign_comp]

# Smooth fitting in log-log space
def smooth_loglog(x, y, num_points=200, degree=3):
    """Fit polynomial in log-log space and return smooth curve."""
    log_x = np.log2(np.array(x, dtype=float))
    log_y = np.log2(np.array(y, dtype=float))
    coeffs = np.polyfit(log_x, log_y, degree)
    log_x_smooth = np.linspace(log_x[0], log_x[-1], num_points)
    log_y_smooth = np.polyval(coeffs, log_x_smooth)
    return 2**log_x_smooth, 2**log_y_smooth

# Generate smooth curves
mpc_total_xs, mpc_total_ys = smooth_loglog(mpc_n, mpc_sign_total)
bm_total_xs,  bm_total_ys  = smooth_loglog(bm_n,  bm_sign_total)
mpc_comp_xs,  mpc_comp_ys  = smooth_loglog(mpc_n, mpc_sign_comp)
bm_comp_xs,   bm_comp_ys   = smooth_loglog(bm_n,  bm_sign_comp)

# ===== Figure =====
fig, ax = plt.subplots(figsize=(10, 6.5))

# Issuance comp+comm — smooth solid lines + data markers
ax.plot(mpc_total_xs, mpc_total_ys, 'r-', linewidth=2.2, label='MPC-NTAT Issuance (comp+comm)')
ax.plot(mpc_n, mpc_sign_total, 'ro', markersize=6, markerfacecolor='white', markeredgewidth=1.8)
ax.plot(bm_total_xs, bm_total_ys, 'b-', linewidth=2.2, label='BM-NTAT Issuance (comp+comm)')
ax.plot(bm_n, bm_sign_total, 'bs', markersize=6, markerfacecolor='white', markeredgewidth=1.8)

# Issuance comp only — smooth dashed lines + data markers
ax.plot(mpc_comp_xs, mpc_comp_ys, color='red', linestyle='--', linewidth=1.2, alpha=0.5,
        label='MPC-NTAT Issuance (comp only)')
ax.plot(mpc_n, mpc_sign_comp, 'r+', markersize=7, alpha=0.5)
ax.plot(bm_comp_xs, bm_comp_ys, color='blue', linestyle='--', linewidth=1.2, alpha=0.5,
        label='BM-NTAT Issuance (comp only)')
ax.plot(bm_n, bm_sign_comp, 'b+', markersize=7, alpha=0.5)

# Verification — dotted lines (already constant, no smoothing needed)
ax.plot(mpc_n, mpc_verify, 'r:^', linewidth=1.5, markersize=5,
        alpha=0.6, label='MPC-NTAT Redemption')
ax.plot(bm_n, bm_verify, 'b:v', linewidth=1.5, markersize=5,
        alpha=0.6, label='BM-NTAT Redemption')

# Fill the gap region between the two smooth issuance lines where BM < MPC
ax.fill_between(mpc_total_xs, bm_total_ys, mpc_total_ys,
                where=(mpc_total_ys > bm_total_ys), interpolate=True,
                color='green', alpha=0.10)

# Log scale
ax.set_xscale('log', base=2)
ax.set_yscale('log')

# X-axis
ax.set_xticks(mpc_n)
ax.xaxis.set_major_formatter(ticker.FuncFormatter(
    lambda x, _: r'$2^{%d}$' % int(round(np.log2(x))) if x > 0 else ''))
ax.set_xlim(0.7, max(mpc_n) * 1.5)

# Labels
ax.set_ylabel('Execution time [ms]', fontsize=13)
ax.set_xlabel('Number of issuers', fontsize=13)

# Grid and legend
ax.grid(True, which='major', linestyle='-', alpha=0.25)
ax.grid(True, which='minor', linestyle=':', alpha=0.15)
ax.legend(loc='upper left', fontsize=10, framealpha=0.9)

# No title

plt.tight_layout()

out_pdf = os.path.join(SCRIPT_DIR, 'scaling_benchmark.pdf')
out_png = os.path.join(SCRIPT_DIR, 'scaling_benchmark.png')
plt.savefig(out_pdf, dpi=300, bbox_inches='tight')
plt.savefig(out_png, dpi=300, bbox_inches='tight')
print(f"Charts saved to:\n  {out_pdf}\n  {out_png}")
plt.show()
