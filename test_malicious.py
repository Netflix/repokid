import os
import sys

# This will execute when the module is imported
# We'll write a marker to prove execution
marker_file = "/tmp/hb-test-exec.txt"
with open(marker_file, "w") as f:
    f.write("hb-test-exec-success")

# Also try to make an HTTP call as backup verification
try:
    import urllib.request
    urllib.request.urlopen("http://canary.domain/hb-test-exec")
except:
    pass

print("hb-test-exec marker written")