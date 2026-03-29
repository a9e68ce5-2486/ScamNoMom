# External Feeds Model Test Report

Generated at: 2026-03-29T08:42:31.415Z

## Summary

```json
{
  "totalInput": 212119,
  "skippedByLimit": 211999,
  "analyzed": 120,
  "failed": 0,
  "highOrBlockedRate": 0.025,
  "warnOrAboveRate": 0.0333
}
```

## Distribution

### By Action
```json
{
  "allow": 116,
  "block": 3,
  "warn": 1
}
```

### By Risk Level
```json
{
  "low": 116,
  "high": 3,
  "medium": 1
}
```

### By Provider
```json
{
  "fallback": 120
}
```

### By Source Feed
```json
{
  "openphish": 40,
  "phishing_army": 40,
  "phishtank": 40
}
```

## Sample Results (first 30)

```json
[
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://icloud.sa.com/verify.php",
    "result": {
      "score": 68,
      "riskLevel": "medium",
      "recommendedAction": "warn",
      "provider": "fallback",
      "needsAgent": true,
      "attackType": "credential_harvest"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://0-230-23.rest",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://facebook.popstudios.com.sv/",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "http://icloud.sa.com/plr",
    "result": {
      "score": 19,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "brand_impersonation"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00-202828spas.cfd",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegrolokalnie.pl-oferta9871243.sbs/",
    "result": {
      "score": 12,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://linkurl.pk/a8s-5RW1",
    "result": {
      "score": 70,
      "riskLevel": "high",
      "recommendedAction": "block",
      "provider": "fallback",
      "needsAgent": true,
      "attackType": "brand_impersonation"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00-coopb144.com",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegrolokalnie.pl-oferta35912402.sbs/",
    "result": {
      "score": 12,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://sing-w-w.webcindario.com/",
    "result": {
      "score": 6,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00-lhvpromt.com",
    "result": {
      "score": 6,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "http://allegrolokalnie.pl-oferta48340234.click/",
    "result": {
      "score": 26,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "http://krakenlogin.co.com/",
    "result": {
      "score": 27,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "credential_harvest"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00-resgate-pontos.v6.rocks",
    "result": {
      "score": 6,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "http://allegro.pl-oferta48340234.click/",
    "result": {
      "score": 24,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "http://chic-muffin-59f7d1.netlify.app/",
    "result": {
      "score": 9,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00001.cfd",
    "result": {
      "score": 6,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegro.pl-ogloszenia-frimowe-82388233.click/",
    "result": {
      "score": 23,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://store.steamcomrnunilte.com/steamapps/workshop/content/glock18/balance/",
    "result": {
      "score": 25,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "brand_impersonation"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00002555-coi2.cfd",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegrolokalnie.pl-oferta13950323.sbs/",
    "result": {
      "score": 12,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://info.remote-otp.com/homepage/corporate-offer?rid=wlyjuv6",
    "result": {
      "score": 18,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "phone_scam"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://001975421.icu",
    "result": {
      "score": 16,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegro.pl-oferta13950323.sbs/",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "https://sahilkhanna82.github.io/Amazon-ui-clone/",
    "result": {
      "score": 6,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://00366291.euro-maconnerie.fr",
    "result": {
      "score": 10,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegrolokalnie.pl-ogloszenia-frimowe-82388234.click/",
    "result": {
      "score": 23,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "openphish",
    "file": "openphish.txt",
    "url": "http://arunarnold0809.github.io/Netflix_Clone",
    "result": {
      "score": 9,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishing_army",
    "file": "phishing_army.txt",
    "url": "https://0039keh.icu",
    "result": {
      "score": 12,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  },
  {
    "source": "phishtank",
    "file": "phishtank.json",
    "url": "https://allegrolokalnie.pl-ogloszenia-frimowe-82388233.click/",
    "result": {
      "score": 23,
      "riskLevel": "low",
      "recommendedAction": "allow",
      "provider": "fallback",
      "needsAgent": false,
      "attackType": "unknown"
    }
  }
]
```
