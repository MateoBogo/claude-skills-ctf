# CTF Forensics - Signals and Hardware

## Table of Contents
- [VGA Signal Decoding](#vga-signal-decoding)
- [HDMI TMDS Decoding](#hdmi-tmds-decoding)
- [DisplayPort 8b/10b + LFSR Decoding](#displayport-8b10b--lfsr-decoding)
- [Voyager Golden Record Audio (0xFun 2026)](#voyager-golden-record-audio-0xfun-2026)
- [Side-Channel Power Analysis (EHAX 2026)](#side-channel-power-analysis-ehax-2026)
- [Saleae Logic 2 UART Decode (EHAX 2026)](#saleae-logic-2-uart-decode-ehax-2026)
- [Flipper Zero .sub File (0xFun 2026)](#flipper-zero-sub-file-0xfun-2026)
- [Keyboard Acoustic Side-Channel (ApoorvCTF 2026)](#keyboard-acoustic-side-channel-apoorvctf-2026)
- [POCSAG Pager Decoding via GQRX → sox → multimon-ng (404CTF 2025)](#pocsag-pager-decoding-via-gqrx--sox--multimon-ng-404ctf-2025)
- [IQ File FFT Masking (out-of-band filter, 404CTF 2025 "Trop d'IQ")](#iq-file-fft-masking-out-of-band-filter-404ctf-2025-trop-diq)
- [PulseView I2C Decoder + Datasheet (404CTF 2025 "Comment est votre température")](#pulseview-i2c-decoder--datasheet-404ctf-2025-comment-est-votre-température)
- [Op-Amp Flash ADC Recovery from Schematic (404CTF 2025 "R16D4")](#op-amp-flash-adc-recovery-from-schematic-404ctf-2025-r16d4)

---

## VGA Signal Decoding

**Frame structure:** 800x525 total (640x480 active + blanking). Each sample = 5 bytes: R, G, B, HSync, VSync. Color is 6-bit (0-63).

```python
import numpy as np
from PIL import Image

data = open('vga.bin', 'rb').read()

TOTAL_W, TOTAL_H = 800, 525
ACTIVE_W, ACTIVE_H = 640, 480
BYTES_PER_SAMPLE = 5  # R, G, B, hsync, vsync

# Parse raw samples
samples = np.frombuffer(data, dtype=np.uint8).reshape(-1, BYTES_PER_SAMPLE)
frame = samples.reshape(TOTAL_H, TOTAL_W, BYTES_PER_SAMPLE)

# Extract active region, scale 6-bit to 8-bit
active = frame[:ACTIVE_H, :ACTIVE_W, :3]  # RGB only
img_arr = (active.astype(np.uint16) * 4).clip(0, 255).astype(np.uint8)
Image.fromarray(img_arr).save('vga_output.png')
```

**Key lesson:** Total frame > visible area — always crop blanking. If colors look dark, check if 6-bit (multiply by 4).

---

## HDMI TMDS Decoding

**Structure:** 3 channels (R, G, B), each encoded as 10-bit TMDS (Transition-Minimized Differential Signaling) symbols. Bit 9 = inversion flag, bit 8 = XOR/XNOR mode. Decode is deterministic from MSBs down.

```python
def tmds_decode(symbol_10bit):
    """Decode a 10-bit TMDS symbol to 8-bit pixel value."""
    bits = [(symbol_10bit >> i) & 1 for i in range(10)]
    # bits[9] = inversion flag, bits[8] = XOR/XNOR mode

    # Step 1: undo optional inversion (bit 9)
    if bits[9]:
        d = [1 - bits[i] for i in range(8)]
    else:
        d = [bits[i] for i in range(8)]

    # Step 2: undo XOR/XNOR chain (bit 8 selects mode)
    q = [d[0]]
    if bits[8]:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1])        # XOR mode
    else:
        for i in range(1, 8):
            q.append(d[i] ^ q[i-1] ^ 1)    # XNOR mode

    return sum(q[i] << i for i in range(8))

# Parse: read 10-bit symbols from binary, group into 3 channels
# Frame is 800x525 total, crop to 640x480 active
```

**Identification:** Binary data with 10-bit aligned structure. Challenge mentions HDMI, DVI, or TMDS.

---

## DisplayPort 8b/10b + LFSR Decoding

**Structure:** 10-bit 8b/10b symbols decoded to 8-bit data, then LFSR-descrambled. Organized in 64-column Transport Units (60 data columns + 4 overhead).

```python
# Standard 8b/10b decode table (partial — full table has 256 entries)
# Use a prebuilt table: map 10-bit symbol -> 8-bit data
# Key: running disparity tracks DC balance

# LFSR descrambler (x^16 + x^5 + x^4 + x^3 + 1)
def lfsr_descramble(data):
    """DisplayPort LFSR descrambler. Resets on control symbols (BS/BE)."""
    lfsr = 0xFFFF  # Initial state
    result = []
    for byte in data:
        out = byte
        for bit_idx in range(8):
            feedback = (lfsr >> 15) & 1
            out ^= (feedback << bit_idx)
            new_bit = ((lfsr >> 15) ^ (lfsr >> 4) ^ (lfsr >> 3) ^ (lfsr >> 2)) & 1
            lfsr = ((lfsr << 1) | new_bit) & 0xFFFF
        result.append(out & 0xFF)
    return bytes(result)

# Transport Unit layout: 64 columns per TU
# Columns 0-59: pixel data (RGB)
# Columns 60-63: overhead (sync, stuffing)
# LFSR resets on control bytes (BS=0x1C, BE=0xFB)
```

**Key lesson:** LFSR scrambler resets on control bytes — identify these to synchronize descrambling. Without reset points, output is garbled.

---

## Voyager Golden Record Audio (0xFun 2026)

**Pattern (11 Lines of Contact):** Analog image encoded as audio. Sync pulses (sharp negative spikes) delimit scan lines. Amplitude between pulses = pixel brightness.

```python
import numpy as np
from scipy.io import wavfile
from PIL import Image

rate, audio = wavfile.read('golden_record.wav')
audio = audio.astype(np.float32)

# Find sync pulses (sharp negative spikes below threshold)
threshold = np.min(audio) * 0.7
sync_indices = np.where(audio < threshold)[0]

# Group consecutive sync samples into pulse starts
pulses = [sync_indices[0]]
for i in range(1, len(sync_indices)):
    if sync_indices[i] - sync_indices[i-1] > 100:
        pulses.append(sync_indices[i])

# Extract scan lines between pulses, resample to fixed width
WIDTH = 512
lines = []
for i in range(len(pulses) - 1):
    line = audio[pulses[i]:pulses[i+1]]
    resampled = np.interp(np.linspace(0, len(line)-1, WIDTH), np.arange(len(line)), line)
    lines.append(resampled)

# Normalize and save as image
img_arr = np.array(lines)
img_arr = ((img_arr - img_arr.min()) / (img_arr.max() - img_arr.min()) * 255).astype(np.uint8)
Image.fromarray(img_arr).save('voyager_image.png')
```

---

## Side-Channel Power Analysis (EHAX 2026)

**Pattern (Power Leak):** Power consumption traces recorded during cryptographic operations. Correct key guesses cause measurably different power consumption at specific sample points.

**Data format:** Typically a multi-dimensional array: `[positions × guesses × traces × samples]`. E.g., 6 digit positions × 10 guesses (0-9) × 20 traces × 50 samples.

**Attack (Differential Power Analysis):**
```python
import numpy as np
import hashlib

# Load power traces: shape = (positions, guesses, traces, samples)
data = np.load('power_traces.npy')  # or parse from CSV/JSON
n_positions, n_guesses, n_traces, n_samples = data.shape

# For each position, find the guess with maximum power at the leak point
key_digits = []
for pos in range(n_positions):
    # Average across traces for each guess
    avg_power = data[pos].mean(axis=1)  # shape: (guesses, samples)

    # Find the sample point with maximum power variance across guesses
    # This is the "leak point" where the correct guess stands out
    variance_per_sample = avg_power.var(axis=0)
    leak_sample = np.argmax(variance_per_sample)

    # The guess with maximum power at the leak point is correct
    best_guess = np.argmax(avg_power[:, leak_sample])
    key_digits.append(best_guess)

key = ''.join(str(d) for d in key_digits)
print(f"Recovered key: {key}")

# Flag may be SHA256 of the key
flag = hashlib.sha256(key.encode()).hexdigest()
```

**Identification:** Challenge mentions "power", "side-channel", "leakage", "traces", or "measurements". Data is a multi-dimensional numeric array with axes for positions/guesses/traces/samples.

**Key insight:** The "leak point" is the sample index where correct vs incorrect guesses show the largest power difference. Average across traces first to reduce noise, then find the sample with maximum variance across guesses.

---

## Saleae Logic 2 UART Decode (EHAX 2026)

**Pattern (Baby Serial):** Saleae Logic 2 `.sal` file (ZIP archive) containing digital channel captures. Data encoded as UART serial.

**File structure:** `.sal` is a ZIP containing `digital-0.bin` through `digital-7.bin` + `meta.json`. Only channel 0 typically has data.

**Binary format (digital-*.bin):**
```text
<SALEAE> magic (8 bytes)
version: u32 = 2
type: u32 = 100 (digital)
initial_state: u32 (0 or 1)
... header fields ...
Delta-encoded transitions (variable-length integers)
```

**Delta encoding:** Each value represents the number of samples between state transitions. The signal alternates between HIGH and LOW at each delta.

**UART decode from deltas:**
```python
import numpy as np

# Parse deltas from binary (after header)
# Reconstruct signal timeline
times = np.cumsum(deltas)
states = []
state = initial_state
for d in deltas:
    states.append(state)
    state ^= 1  # toggle on each transition

# UART decode: detect start bit (HIGH→LOW), sample 8 data bits at bit centers
# Baud rate detection: most common delta ≈ samples_per_bit
# At 1MHz sample rate: 115200 baud ≈ 8.7 samples/bit

def uart_decode(transitions, sample_rate=1_000_000, baud=115200):
    bit_period = sample_rate / baud
    bytes_out = []
    i = 0
    while i < len(transitions):
        # Find start bit (falling edge)
        if transitions[i] == 0:  # LOW = start bit
            byte_val = 0
            for bit in range(8):
                sample_time = (1.5 + bit) * bit_period  # center of each bit
                # Sample signal at this offset from start bit
                bit_val = get_signal_at(sample_time)
                byte_val |= (bit_val << bit)  # LSB first
            bytes_out.append(byte_val)
        i += 1
    return bytes(bytes_out)
```

**Common pitfalls:**
- **Inverted polarity:** UART idle is HIGH (mark). If initial_state=1, the encoding may be inverted — try both
- **Baud rate guessing:** Check common rates: 9600, 19200, 38400, 57600, 115200, 230400
- **Output format:** Decoded bytes may be base64-encoded (containing a PNG image or text)
- **Saleae internal format ≠ export format:** The `.sal` internal binary uses a different encoding than CSV/binary export. Parse the raw delta transitions directly

**Quick approach:** Install Saleae Logic 2, open the `.sal` file, add UART analyzer with auto-baud detection, export decoded data.

---

## Flipper Zero .sub File (0xFun 2026)

RAW_Data binary -> filter noise bytes (0x80-0xFF) -> expand batch variable references -> XOR with hint text.

---

## Keyboard Acoustic Side-Channel (ApoorvCTF 2026)

**Pattern (Author on the Run):** Recover typed text from audio recordings of keystrokes. Reference audio provides labeled samples (known keys), flag audio contains unknown keystrokes to classify.

**Step 1 — Detect keystrokes via energy peaks:**
```python
import numpy as np
from scipy.signal import find_peaks
from scipy.io import wavfile

sr, audio = wavfile.read('flag.wav')
if audio.ndim > 1:
    audio = audio.mean(axis=1)

# Sliding window energy envelope (10ms window)
win = int(0.01 * sr)
energy = np.array([np.sum(audio[i:i+win]**2) for i in range(0, len(audio) - win, win)])

# Find peaks with minimum 175ms separation
min_dist = int(0.175 * sr / win)
peaks, _ = find_peaks(energy, height=0.03 * energy.max(), distance=min_dist)
```

**Step 2 — Extract MFCC features per keystroke:**
```python
import librosa

def extract_features(audio, sr, peak_sample, window_ms=10):
    win = int(window_ms / 1000 * sr)
    start = max(0, peak_sample - win // 2)
    segment = audio[start:start + win]
    mfccs = librosa.feature.mfcc(y=segment.astype(float), sr=sr, n_mfcc=20)
    return np.concatenate([mfccs.mean(axis=1), mfccs.std(axis=1)])  # 40-dim
```

**Step 3 — Classify with KNN against labeled reference:**
```python
from sklearn.neighbors import KNeighborsClassifier

# Build reference from labeled audio (26 keys × 50 presses each)
X_ref, y_ref = [], []
for key_idx, key in enumerate('abcdefghijklmnopqrstuvwxyz'):
    for peak in reference_peaks[key_idx * 50:(key_idx + 1) * 50]:
        X_ref.append(extract_features(ref_audio, sr, peak))
        y_ref.append(key)

knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_ref, y_ref)

# Classify flag keystrokes
flag = ''.join(knn.predict([extract_features(flag_audio, sr, p) for p in flag_peaks]))
```

**Key insight:** Window size is critical — 10ms captures the initial impact transient which is most distinctive per key. Larger windows (20-30ms) include key release noise that reduces classification accuracy. Use all individual reference samples rather than averaging, as KNN handles variance better with more data points.

**Detection:** Two audio files provided (reference + target), or challenge mentions "typing", "keyboard", "acoustic".

---

## POCSAG Pager Decoding via GQRX → sox → multimon-ng (404CTF 2025)

**Pattern:** challenge gives an IQ capture (or live SDR feed) of a narrowband FM pager channel (typically 137–169 MHz or 448 MHz). Decode chain:

```bash
# 1) GQRX demodulates FM and sends raw audio to UDP (Settings → Audio → UDP sink, localhost:7355)
# 2) sox converts that UDP stream to 22050 Hz mono signed 16-bit PCM for multimon-ng
nc -l -u 7355 | sox -t raw -r 48000 -e signed -b 16 -c 1 - -t raw -r 22050 -e signed -b 16 -c 1 - \
  | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -f alpha /dev/stdin
```

Key flags:
- `-a POCSAG512/1200/2400` — try all three baud rates (challenge doesn't tell you).
- `-f alpha` — alphanumeric mode so text flag appears in place of numeric codewords.

**Offline version** (IQ file → WAV → decode):
```bash
# Demodulate NFM with csdr or GNU Radio, output 22050 Hz mono WAV
csdr convert_u8_f < iq.bin | csdr fmdemod_quadri_cf | csdr limit_ff \
    | csdr fractional_decimator_ff 2.1768707 | csdr deemphasis_nfm_ff 22050 \
    | sox -t raw -r 22050 -e float -b 32 -c 1 - out.wav
multimon-ng -a POCSAG1200 -f alpha out.wav
```

**Spot signal:** narrow (~12.5 kHz) channel, chirpy "pager tones" audible, 1200 bps square-wave morphology on a waterfall.

Source: [acmo0.org/2025-06-01-404CTF-2025-Hardware-Writeup](https://www.acmo0.org/2025-06-01-404CTF-2025-Hardware-Writeup/).

---

## IQ File FFT Masking (out-of-band filter, 404CTF 2025 "Trop d'IQ")

**Pattern:** you get a complex IQ file (`complex64` or `complex128`) where the payload lives in a narrow band — audio voice or digital chirp — but the capture is polluted by noise at higher/lower frequencies. Classic: zero out unwanted FFT bins, inverse-FFT, listen/demod.

```python
import numpy as np, scipy.io.wavfile as wav
iq = np.fromfile('capture.iq', dtype=np.complex128)    # or complex64
fs = 48000                                              # sample rate

X = np.fft.fft(iq)
freqs = np.fft.fftfreq(len(iq), 1/fs)

# Keep only 300 Hz .. 3 kHz (voice band); zero everything else
mask = (np.abs(freqs) >= 300) & (np.abs(freqs) <= 3000)
X[~mask] = 0

clean = np.fft.ifft(X).real
clean = np.int16(clean / np.max(np.abs(clean)) * 32767)
wav.write('voice.wav', fs, clean)
```

For "remove upper half of FFT" (the 404CTF instance): set `X[len(X)//2:] = 0` before ifft — effectively a 22 kHz low-pass on a 44 kHz-sampled IQ.

**Extension:** if payload is digital (BPSK/FSK) in-band, after masking use `numpy.angle` / `scipy.signal.hilbert` then thresholding for bit recovery.

---

## PulseView I2C Decoder + Datasheet (404CTF 2025 "Comment est votre température")

**Pattern:** logic analyser trace (`.sr` / `.srzip` / Saleae `.logicdata`) shows I²C traffic between MCU and a sensor. Flag is encoded in the sensor's measurements — you must decode both the protocol and the sensor's response format.

**Workflow:**
1. Open the capture in PulseView (`pulseview capture.sr`).
2. Assign **I2C** protocol decoder → set `SCL` / `SDA` channels → view decoded frames.
3. Identify sensor from the I²C address (e.g. `0x44` → SHT40 family; `0x48` → LM75; `0x76/0x77` → BME280).
4. Pull the datasheet. Map command bytes to measurements:
   - SHT40: `0xFD` → high-precision measurement (returns 6 bytes: T_msb T_lsb CRC RH_msb RH_lsb CRC)
   - Convert: `T_degC = -45 + 175 * raw_T / 65535`, `RH = -6 + 125 * raw_RH / 65535`.
5. String the decoded measurement series into ASCII/bits/characters per the challenge hint.

**CLI alternative (sigrok-cli):**
```bash
sigrok-cli -i capture.sr -P i2c:scl=D0:sda=D1 -A i2c=data-read,data-write,address-read,address-write
```

**Key lesson:** PulseView does the protocol layer; the *datasheet* does the semantic layer. Never skip the datasheet — flag often encodes in the exact scaling formula.

---

## Op-Amp Flash ADC Recovery from Schematic (404CTF 2025 "R16D4")

**Pattern:** schematic shows a stack of identical op-amps, each wired as a **comparator** against a voltage-divider reference, outputs feeding into a priority encoder or directly sampled by an MCU. This is a classic **flash ADC** — `N` comparators quantise an input into `log2(N+1)` bits.

**Recovery steps:**
1. Count comparators (N). Flash ADC width is typically `ceil(log2(N+1))`.
2. Compute per-comparator reference: `V_ref_i = V_cc * i / (N+1)` (resistor ladder).
3. For each input sample: count how many comparators are at `V_cc` (high) — that count, divided by `V_cc/(N+1)`, gives the quantised integer.
4. The MCU firmware or Arduino code usually reads the encoder output → match the pin order to reconstruct the bit pattern.

**Worked example (N=15, 4-bit):**
```
V_cc = 5 V, 15 comparators at 5/16, 10/16, ..., 75/16 V
Input = 2.0 V → comparators 1..6 high (6/16 * 5 = 1.875 V threshold crossed, 7th at 2.19 V not)
Raw value = 6 (4-bit)
```

**Spot signal:** schematic with N ≈ 2^k - 1 op-amps sharing a common input node and distinct reference taps from a resistor ladder; Arduino sketch that reads a parallel port and looks it up in a small ROM table.

**Datasheet tie-in:** LM339 / LM393 (quad comparators) are the dead giveaway. MAX152 / MAX1106 are integrated 8-bit flash ADCs that follow the same math if the challenge uses an IC instead of discrete op-amps.

## TVLA / Welch-t Leakage Assessment (source: ChipWhisperer + modern side-channel CTFs)

**Trigger:** power/EM traces provided; challenge asks "does this implementation leak" or gives two trace-sets (fixed-key vs random-key, or fixed-plaintext vs random-plaintext).
**Signals:** `.npy` / `.bin` / `.trs` file with N × T samples; filename mentions `fixed_vs_random`, `tvla`, `key_t`, `key_r`; README references Goodwill et al. NIST TVLA methodology.
**Mechanic:** Welch's *t*-test per time sample — if `|t| > 4.5` for any sample, the set pair is leaking at 99.999 % confidence. Sample-complexity scales as `O(SNR^-2)`, so a clean 10k-trace set often wins where 1k fails.

```python
import numpy as np
# traces_f, traces_r : np.ndarray, shape (N_traces, N_samples)
def welch_t(a, b):
    ma, mb = a.mean(0), b.mean(0)
    va, vb = a.var(0, ddof=1), b.var(0, ddof=1)
    return (ma - mb) / np.sqrt(va / a.shape[0] + vb / b.shape[0])
t = welch_t(traces_f, traces_r)
leak_idx = np.where(np.abs(t) > 4.5)[0]     # time samples that leak
```

**Second-order:** center each trace (subtract mean), square, then re-run Welch — catches masked implementations where first-order TVLA is flat but the variance still leaks.

**CPA after TVLA:** once leakage localised, pivot to Correlation Power Analysis (Pearson ρ between hypothesis Hamming-weight(sbox output) and trace value). Libraries: `scared`, `lascar`, `estraces`.

## Morphology-Over-Duration Side-Channel (source: 404CTF 2024 Sea Side Channel + CSIDH)

**Trigger:** implementation uses "constant-time" APIs (`memcmp_ct`, `mpz_powm_sec`) yet leaks; traces have equal **length** but visibly different **shape** under a microscope.
**Signals:** waveforms all same length → naive timing attack fails; challenge provides a scope capture at ≥ 100 MS/s per op.
**Mechanic:** don't compare total time — compare per-window morphology (min, max, mean, autocorrelation, FFT bins) in a sliding window of 1-10 ops. Cluster by k-means on the 4D feature vector. The two clusters correspond to the two secret-bit values. Effective on CSIDH isogeny chains, constant-time Curve25519 ladders with subnormal paths, and SM2 / SM9 Chinese curves.

## CPA on AES-TinyAES / MBED Hamming-Weight

**Trigger:** traces labelled with known plaintexts; target is AES-128 first round; platform STM32 / ATMega.
**Signal:** 5000-10000 traces, 10-50k samples each, plaintext in a separate `.npy`.
**Mechanic:** CPA on Hamming weight of `sbox(p ⊕ k)` for each byte position:

```python
from scipy.stats import pearsonr
hw = bytes.fromhex("0001010201020203…" * 32)  # precomputed HW of 0..255
def cpa(traces, plaintexts, byte_pos):
    correlations = np.zeros((256, traces.shape[1]))
    for k in range(256):
        h = np.array([hw[AES_SBOX[p[byte_pos] ^ k]] for p in plaintexts])
        correlations[k] = np.array([pearsonr(h, traces[:, t])[0]
                                    for t in range(traces.shape[1])])
    return correlations.max(1).argmax()  # best key guess
```

Expect one key byte in < 1s on 10k traces; loop over 16 byte positions.
