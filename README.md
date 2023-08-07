# Pouch

Pouch is a *fork* of [drduh/purse](https://github.com/drduh/Purse) built with [age](https://github.com/FiloSottile/age) and [gum](https://github.com/charmbracelet/gum).

## Use

This script requires an age identity - see [FiloSottile/age](https://github.com/FiloSottile/age).

Set your age recipient with `export POUCH_AGE_RECIPIENT=age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p` and your age identity file with `export POUCH_AGE_IDENTITY=~/key.txt`, or edit `pouch.sh`.

Fully supports [str4d/age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) for age identities stored on YubiKeys, just change `POUCH_AGE_IDENTITY` to reference the file generated by `age-plugin-yubikey`, often named `age-yubikey-identity-...txt`.
