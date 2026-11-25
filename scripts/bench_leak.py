import random
import string
import time

from src.engine import output_scanner as osc

random.seed(1)
vocab = ["".join(random.choices(string.ascii_lowercase, k=random.randint(3, 9))) for _ in range(5000)]


def make_prompt(n_chars):
    out, size = [], 0
    while size < n_chars:
        w = random.choice(vocab)
        out.append(w)
        size += len(w) + 1
    return " ".join(out)


for n in (50_000, 200_000, 1_000_000):
    prompt = make_prompt(n)
    completion = "Sure, here it is: " + prompt[-2000:]  # leak from the TAIL
    osc._shingle_cache.clear()
    t0 = time.perf_counter()
    info = osc.detect_system_prompt_leak_ex(completion, prompt, max_system_chars=2_000_000)
    cold = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    osc.detect_system_prompt_leak_ex(completion, prompt, max_system_chars=2_000_000)
    warm = (time.perf_counter() - t0) * 1000
    print(f"{n:>9} chars  cold={cold:8.1f} ms  warm={warm:7.2f} ms  leak_found={bool(info.spans)}  truncated={info.truncated}")