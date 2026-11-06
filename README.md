# apk-domains

applications.csv -> download APK -> unzip (xapk/apks too) -> apktool + jadx decompile -> extract every domain
(static, API, CDN, runtime) -> classify with local Llama 3 (Ollama) -> CSV/JSON.

## Setup
    ollama pull llama3.1:8b && ollama serve
    pip install -r requirements.txt
    # CLI tools (all optional, features degrade gracefully):
    #   apkeep  (cargo install apkeep)    - APK download   (fallback: APKPure URL)
    #   apktool, jadx                      - decompile
    #   adb + PCAPdroid on emulator, tshark - runtime capture
    #   ipatool                            - iOS IPA download (needs Apple login)

## applications.csv
    name,package
    Bing,com.microsoft.bing
    Spotify,                    # package resolved via Play Store search

## Run
    python main.py batch applications.csv --resume
    python main.py batch applications.csv --suggest --expand
    python main.py batch applications.csv --dynamic --pcapdroid-key KEY
    python main.py apk bing.apk --name Bing --package com.microsoft.bing
    python main.py apk app.apk --pcap capture.pcap      # add traffic captured elsewhere
    python main.py apk app.apk --no-llm --no-decompile  # fastest

## Output
    output/<AppName>.txt     one related domain per line (first-party + API + CDN), nothing else
    output/failed.txt        apps that failed (download etc.): name | package | reason
    --full-report            also save every domain with category/is_api/source as CSV

Fast by default: rules only (no Llama), apktool decode, apps processed 4 in parallel.
Opt-in extras: --jadx (Java decompile, slower, finds more), --llm (Llama on leftover unknown domains),
--expand (crt.sh), --dynamic / --pcap (runtime traffic).

## Limits
- Google Play / App Store downloads are restricted; apkeep/APKPure cover many but not all apps.
  Drop files into downloads/<package>.apk to use your own.
- Static analysis misses runtime-built and remote-config domains -> use --dynamic or --pcap.
- Runtime capture uses random UI events (monkey); apps behind login need a logged-in emulator.
- PCAPdroid's intent API/output path can differ by version; check the one-time setup in dynamic.py.
