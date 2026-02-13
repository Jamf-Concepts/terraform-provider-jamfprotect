## File Path
The location of an item starting at the root of the file system. Wildcards are supported to implement exceptions for FilePath.

### Example:
/tmp/log/*
/Users/*/Pictures/Photos Library.photoslibrary/resources/*
*/Library/Cookies/Cookies.binarycookies*

## Signing ID
An application's identifier, such as com.apple.calculator. Signing ID requires both a Team ID and an App ID or Signing ID. This only applies to Endpoint Threat Prevention, Process, File, Click, and Keylogger events.

Both the App ID and Signing ID of an application can be found by running the codesign command line utility from the terminal.

codesign -dv /Applications/JamfProtect.app

### Example:
com.jamf.protect.daemon

## Platform Binary
A platform binary is built into macOS and is specially signed by Apple. These specially signed binaries do not have an associated Team ID, and are referenced by the App ID, such as com.apple.calculator.

The App ID of a platform binary can be found by running the codesign command line utility from the terminal.

codesign -dv /System/Applications/Calculator.app

### Example:
com.apple.calculator
com.apple.news.widget
com.apple.photolibraryd

## Team ID
A unique code issued by Apple that identifies an application developer in the signed certificate. Team IDs are formatted alphanumerically, such as "526FTYP998". This only applies to Endpoint Threat Prevention, Process, File, Click, and Keylogger events.

The Team ID of an application can be found by running the codesign command line utility from the terminal

codesign -dv /Applications/JamfProtect.app

### Example:
483DWKW443

## Process Path
The full path to an application or binary. The path is responsible for the system event or activity targeted by an exception, such as File, Keylogger, and Click events, or to the application itself being launched (process event) or prevented (Endpoint Threat Prevention). Wildcards are supported to implement exceptions for Process Path.

### Example:
/Applications/1Password/7.app
/System/Applications/Calculator.app
/Applications/ThisApp.app

## User
The user account name responsible for generating the event on the monitored computer. This can include system accounts. Examples of user and system accounts are:

User Account:

janet.smith
System Account:

jamfpro

---

Wildcard Support
File path and process path exceptions provide support for Unix shell-style wildcards. Unix shell wildcards and Regular Expressions are similar, however the two are not explicitly interchangeable.

*
Matches everything

?
Matches any single character

[seq]
Matches any character in seq

[!seq]
Matches any character not in seq

For a literal match, wrap the meta-character in brackets. Typing [*] matches the character * instead of using it as a wildcard. For example, to match 'Application/data/*profiletemplate' enter 'Application/Data/[*]profiletemplate'.
