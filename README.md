# Form-Text-Sanitizer

form-text-sanitizer is a super-fast string sanitizer checking for HTML, SVG, ERB, and Mustache Expressions that may be contained inside input text. It is intended to prevent XSS Attacks.

## Usage

Installation:
```bash
npm i form-text-sanitizer
```

Import the `checkAndSanitizeString` function to your JavaScript file: 
```js
import checkAndSanitizeString from "form-text-sanitizer";
```

Input the string you wish to sanitize and (optionally) destructure the response:
```js
const { originalString, suggestedString, matches } = checkAndSanitizeString("My message: <Script>alert('XSS')</SCRIPT>End message.");
```

In the above example the response will be:
```js
  {
    originalString: "My message: <script>alert('XSS')</SCRIPT>End message.",
    suggestedString: "My message: End message.",
    matches: ["<script>alert('XSS')</SCRIPT>"]
  }
```

`originalString` - User input string

`suggestedString` - Sanitized string

`matches` - Array of string(s) that are potentially malicious. 
This can be empty if no such strings are detected. In this case, `suggestedString` and `originalString` will be the same.
