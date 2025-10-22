# SSH Banner Files

## Available Banners

### English (Original)
**File:** `sshd_banner`
- Standard English warning
- For English-speaking environments

### Welsh (Cymraeg)
**File:** `sshd_banner_cy`
- Complete Welsh translation
- "Mynediad Awdurdodedig yn Unig"
- For Welsh-speaking environments

### Bilingual (English/Welsh)
**File:** `sshd_banner_bilingual`
- Both Welsh and English
- Welsh first, then English
- Ideal for Wales-based servers
- Complies with Welsh Language Standards

## Installation

Choose the appropriate banner for your environment:

### For English only:
```bash
sudo cp sshd_banner /etc/ssh/sshd_banner
```

### For Welsh only:
```bash
sudo cp sshd_banner_cy /etc/ssh/sshd_banner
```

### For Bilingual (Recommended for Wales):
```bash
sudo cp sshd_banner_bilingual /etc/ssh/sshd_banner
```

Then ensure your SSH config includes:
```bash
sudo nano /etc/ssh/sshd_config
# Add or verify this line:
Banner /etc/ssh/sshd_banner

# Restart SSH
sudo systemctl restart sshd
```

## Welsh Translation Notes

The Welsh version maintains the legal meaning of the original English text:

- **"AUTHORIZED ACCESS ONLY"** → **"MYNEDIAD AWDURDODEDIG YN UNIG"**
- **"monitored and logged"** → **"monitro a chofnodi"** (monitored and recorded)
- **"Unauthorized access"** → **"mynediad anawdurdodedig"**
- **"legal action"** → **"camau cyfreithiol"**
- **"consent"** → **"cydsynio"**
- **"disconnect immediately"** → **"datgysylltwch ar unwaith"**

## Welsh Language Standards Compliance

If your organization is in Wales and subject to Welsh Language Standards, the bilingual banner:
- Presents Welsh first (required by standards)
- Provides English translation
- Ensures equal prominence
- Maintains legal clarity in both languages

## Testing

Test your banner before applying:
```bash
cat /etc/ssh/sshd_banner
```

Or connect to see it in action:
```bash
ssh localhost
```

---

**Pob lwc gyda diogelwch eich gweinydd!** (Good luck with your server security!)

