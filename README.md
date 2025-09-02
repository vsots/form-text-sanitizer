# Form-Text-Sanitizer

form-text-sanitizer is a super-fast string sanitizer checking for HTML, SVG, ERB, and Mustache Expressions that may be contained inside input text. It also validates email addresses. It is intended to prevent XSS Attacks.

## Usage

Installation:
```bash
npm i form-text-sanitizer
```

Import the default `sanitizeAndValidate` object to your JavaScript file: 
```js
import sanitizeAndValidate from "form-text-sanitizer";
```

### Sanitize String Inputs

Call the `checkAndSanitizeString` function and input the string you wish to sanitize and (optionally) destructure the response:
```js
const { originalString, suggestedString, matches } = sanitizeAndValidate.checkAndSanitizeString("My message: <Script>alert('XSS')</SCRIPT>End message.");
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

### Validate Email Addresses

Call the `isValidFullEmailAddress` function and input the email (as a string) you wish to validate:
```js
  const isValid = await sanitizeAndValidate.isValidFullEmailAddress(String.raw`
    mytest\@the@mytest.org
  `);
```

In the above example, the response returned is: `true`. This means the email address is valid. The reson this an `async` function is that it contains a call to `dns` for checking the email addresse's domain.

It is recommended to use `String.raw` for the email-address string input, as the escape character and control characters are visible during validation.

Internationalization is [not yet supported](https://github.com/vsots/form-text-sanitizer/issues/2).
