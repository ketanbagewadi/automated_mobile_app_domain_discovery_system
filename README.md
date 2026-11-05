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
    name,package,platform
    Bing,com.microsoft.bing,android
    Spotify,,android            # package resolved via Play Store search

## Run
    python main.py batch applications.csv --resume
    python main.py batch applications.csv --suggest --expand
    python main.py batch applications.csv --dynamic --pcapdroid-key KEY
    python main.py apk bing.apk --name Bing --package com.microsoft.bing
    python main.py apk app.apk --pcap capture.pcap      # add traffic captured elsewhere
    python main.py apk app.apk --no-llm --no-decompile  # fastest

## Output
    output/<package>/domains.csv|json   domain, registered_domain, category, related, is_api,
                                        api_evidence, sample_paths, confidence, reason, source
    output/all_domains.csv              every app combined
    output/failed.csv                   apps that failed + why

`source` shows where each domain came from: dex, manifest, resources, native, assets, apktool, jadx,
dynamic, llm_suggested, crtsh. `is_api` = host label (api., gw., graph.), API-style paths (/v1/, /api/),
or HTTP-client base-URL constants. `retrofit_endpoints` in the JSON lists @GET/@POST paths from jadx output.

## Limits
- Google Play / App Store downloads are restricted; apkeep/APKPure cover many but not all apps.
  Drop files into downloads/<package>.apk to use your own.
- Static analysis misses runtime-built and remote-config domains -> use --dynamic or --pcap.
- Runtime capture uses random UI events (monkey); apps behind login need a logged-in emulator.
- PCAPdroid's intent API/output path can differ by version; check the one-time setup in dynamic.py.
