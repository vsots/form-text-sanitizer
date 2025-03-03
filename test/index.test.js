import checkAndSanitizeString from '../dist/index.js';
import assert from 'assert';

describe('String Matcher and Sanitizer', function() {
    /*
    *   Non-Strings
    */
    it('should return an error when encountering a non-string', function() {
        const testInvalidInput = 4;
        const error = checkAndSanitizeString(testInvalidInput);

        assert.equal(error instanceof Error, true);
        assert.equal(error.message, 'number is not a string');
    })

    /*
    *   Basic HTML Sanitizing
    */
    it('should match basic tags', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT> Previous tags should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Previous tags should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Basic Mustache Sanitizing
    */
    it('should match basic mustache expressions', function() {
        const testString = `This is a test input. {{XSS}} Mustache should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Mustache should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Basic Combination HTML and Mustache Sanitizing
    */
    it('should match basic mustache expressions', function() {
        const testString = `This is a test input. <SCRIPT SRC=https://cdn.jsdelivr.net/host-xss.rocks/index.js></SCRIPT>{{XSS}} Mustache and HTML should not appear.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `This is a test input.  Mustache and HTML should not appear.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Malformed IMG Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-img-tags
    */
    it('should match malformed img tags', function() {
        const testString = `Begin Test<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>End Test`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin TestEnd Test`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   No Closing Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#no-closing-script-tags
    */
    it('should match non-closing script tags', function() {
        const testString = `Begin test <SCRIPT SRC=http://xss.rocks/xss.js?< B > End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Half Open HTML/JavaScript XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#half-open-htmljavascript-xss-vector
    */
    it('should match half-open html', function() {
        const testString = `Begin test <IMG SRC="\`<javascript:alert>\`('XSS')" End Test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);
        
        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   XSS Using HTML Quote Encapsulation
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-using-html-quote-encapsulation
    */
    it('should match XSS Using HTML Quote Encapsulation', function() {
        const testString1 = `<SCRIPT a="><" SRC="httx://xss.rocks/xss.js"`;
        const testString2 = `<SCRIPT ="><" SRC="httx://xss.rocks/xss.js"`;
        const testString3 = `<SCRIPT a="><" '' SRC="httx://xss.rocks/xss.js"`;
        const testString4 = `<SCRIPT "a='><'" SRC="httx://xss.rocks/xss.js"`;
        const testString5 = `<SCRIPT a=\`><\` SRC="httx://xss.rocks/xss.js"`;
        const testString6 = `<SCRIPT a="><'><" SRC="httx://xss.rocks/xss.js"`;
        const testString7 = `<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>`;

        const expectedString = '';

        const result1 = checkAndSanitizeString(testString1);
        const result2 = checkAndSanitizeString(testString2);
        const result3 = checkAndSanitizeString(testString3);
        const result4 = checkAndSanitizeString(testString4);
        const result5 = checkAndSanitizeString(testString5);
        const result6 = checkAndSanitizeString(testString6);
        const result7 = checkAndSanitizeString(testString7);

        assert.equal(result1.originalString, testString1);
        assert.equal(result1.suggestedString, expectedString);
        assert.equal(result1.matches.length, 1);

        assert.equal(result2.originalString, testString2);
        assert.equal(result2.suggestedString, expectedString);
        assert.equal(result2.matches.length, 1);

        assert.equal(result3.originalString, testString3);
        assert.equal(result3.suggestedString, expectedString);
        assert.equal(result3.matches.length, 1);

        assert.equal(result4.originalString, testString4);
        assert.equal(result4.suggestedString, expectedString);
        assert.equal(result4.matches.length, 1);

        assert.equal(result5.originalString, testString5);
        assert.equal(result5.suggestedString, expectedString);
        assert.equal(result5.matches.length, 1);

        assert.equal(result6.originalString, testString6);
        assert.equal(result6.suggestedString, expectedString);
        assert.equal(result6.matches.length, 1);

        assert.equal(result7.originalString, testString7);
        assert.equal(result7.suggestedString, expectedString);
        assert.equal(result7.matches.length, 1);
    })

    /*
    *   Multiple Angle Brackets with Encoding
    */
    it('should match multiple opening and closing angle brackets with different encodings', function() {
        const testString = `Begin test &lt;1234gjfk onload=alert('XSS')  Testing&#00062 <&#x0003csome things&#x3e some more&gt; End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Multiple Curly Brackets with Encoding
    */
    it('should match multiple opening and closing curly brackets with different encodings', function() {
        const testString = `Begin test &lcub;%7b one &rcub}{{}}twothree&#0123;&#x007b&#x7d;&#000000125;&#x07b&#x007b} tester&#x007d;&rcub; End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test  End test.`;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 1);
    })

    /*
    *   Multiple Double Quotes with Encoding
    */
    it('should match multiple double quotes with different encodings', function() {
        const testString = `Begin test <<&quot;"testing&#34;<&#0034> <testing %22> &#x22;>&#x0022 &#00000034;<&#x00000022;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Multiple Single Quotes with Encoding
    */
    it('should match multiple single quotes with different encodings', function() {
        const testString = `Begin test <<&apos;'testing&#39;<&#0039> <testing %27> &#x27;>&#x0027 &#00000039;<&#x00000027;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   Multiple Backticks with Encoding
    */
    it('should match multiple backticks with different encodings', function() {
        const testString = `Begin test <<\`&DiacritICALGRAVE;testing&#96;<&#0096> <testing %60> &#x60;>&#x0060 &#00000096;>&DiacritICALGRAVE;< End test.`;
        const { originalString, suggestedString, matches } = checkAndSanitizeString(testString);

        const expectedString = `Begin test `;

        assert.equal(originalString, testString);
        assert.equal(suggestedString, expectedString);
        assert.equal(matches.length, 2);
    })

    /*
    *   WAF ByPass Strings for XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#waf-bypass-strings-for-xss
    */
    it('should match WAF ByPass Strings for XSS', function() {
        const testString1 = `<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">`;
        const testString2 = `<Video> <source onerror = "javascript: alert (XSS)">`;
        const testString3 = `<Input value = "XSS" type = text>`;
        const testString4 = `<applet code="javascript:confirm(document.cookie);">`;   
        const testString5 = `<isindex x="javascript:" onmouseover="alert(XSS)">`;
        const testString6 = `"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>`;
        const testString7 = `"><img src="x:x" onerror="alert(XSS)">`;
        const testString8 = `"><iframe src="javascript:alert(XSS)">`;
        const testString9 = `<object data="javascript:alert(XSS)">`;
        const testString10 = `<isindex type=image src=1 onerror=alert(XSS)>`;
        const testString11 = `<img src=x:alert(alt) onerror=eval(src) alt=0>`;
        const testString12 = `<img src="x:gif" onerror="window['al\u0065rt'](0)"></img>`;
        const testString13 = `<iframe/src="data:text/html,<svg onload=alert(1)>">`;
        const testString14 = `<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>`;
        const testString15 = `<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script`;
        const testString16 = `<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">`;
        const testString17 = `<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>`;
        const testString18 = `<form><a href="javascript:\u0061lert(1)">X`;
        const testString19 = `</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror='eval(src)'>`;
        const testString20 = `<style>//*{x:expression(alert(/xss/))}//<style></style>`;
        const testString21 = `<img src="/" =_=" title="onerror='prompt(1)'">`;
        const testString22 = `<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ClickMe`;
        const testString23 = `<script x> alert(1) </script 1=2`;
        const testString24 = `<form><button formaction=javascript&colon;alert(1)>CLICKME`;
        const testString25 = `<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"`;
        const testString26 = `<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>`;
        const testString27 = `<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>`;
        
        const expectedString1 = '';
        const expectedString2 = '">';
        const expectedString3 = 'X';
        const expectedString4 = "ClickMe";
        const expectedString5 = "CLICKME";

        const result1 = checkAndSanitizeString(testString1);
        const result2 = checkAndSanitizeString(testString2);
        const result3 = checkAndSanitizeString(testString3);
        const result4 = checkAndSanitizeString(testString4);
        const result5 = checkAndSanitizeString(testString5);
        const result6 = checkAndSanitizeString(testString6);
        const result7 = checkAndSanitizeString(testString7);
        const result8 = checkAndSanitizeString(testString8);
        const result9 = checkAndSanitizeString(testString9);
        const result10 = checkAndSanitizeString(testString10);
        const result11 = checkAndSanitizeString(testString11);
        const result12 = checkAndSanitizeString(testString12);
        const result13 = checkAndSanitizeString(testString13);
        const result14 = checkAndSanitizeString(testString14);
        const result15 = checkAndSanitizeString(testString15);
        const result16 = checkAndSanitizeString(testString16);
        const result17 = checkAndSanitizeString(testString17);
        const result18 = checkAndSanitizeString(testString18);
        const result19 = checkAndSanitizeString(testString19);
        const result20 = checkAndSanitizeString(testString20);
        const result21 = checkAndSanitizeString(testString21);
        const result22 = checkAndSanitizeString(testString22);
        const result23 = checkAndSanitizeString(testString23);
        const result24 = checkAndSanitizeString(testString24);
        const result25 = checkAndSanitizeString(testString25);
        const result26 = checkAndSanitizeString(testString26);
        const result27 = checkAndSanitizeString(testString27);

        assert.equal(result1.originalString, testString1);
        assert.equal(result1.suggestedString, expectedString1);
        assert.equal(result1.matches.length, 1);

        assert.equal(result2.originalString, testString2);
        assert.equal(result2.suggestedString, expectedString1);
        assert.equal(result2.matches.length, 1);

        assert.equal(result3.originalString, testString3);
        assert.equal(result3.suggestedString, expectedString1);
        assert.equal(result3.matches.length, 1);

        assert.equal(result4.originalString, testString4);
        assert.equal(result4.suggestedString, expectedString1);
        assert.equal(result4.matches.length, 1);

        assert.equal(result5.originalString, testString5);
        assert.equal(result5.suggestedString, expectedString1);
        assert.equal(result5.matches.length, 1);

        assert.equal(result6.originalString, testString6);
        assert.equal(result6.suggestedString, expectedString2);
        assert.equal(result6.matches.length, 1);

        assert.equal(result7.originalString, testString7);
        assert.equal(result7.suggestedString, expectedString2);
        assert.equal(result7.matches.length, 1);

        assert.equal(result8.originalString, testString8);
        assert.equal(result8.suggestedString, expectedString2);
        assert.equal(result8.matches.length, 1);

        assert.equal(result9.originalString, testString9);
        assert.equal(result9.suggestedString, expectedString1);
        assert.equal(result9.matches.length, 1);

        assert.equal(result10.originalString, testString10);
        assert.equal(result10.suggestedString, expectedString1);
        assert.equal(result10.matches.length, 1);

        assert.equal(result11.originalString, testString11);
        assert.equal(result11.suggestedString, expectedString1);
        assert.equal(result11.matches.length, 1);

        assert.equal(result12.originalString, testString12);
        assert.equal(result12.suggestedString, expectedString1);
        assert.equal(result12.matches.length, 1);

        assert.equal(result13.originalString, testString13);
        assert.equal(result13.suggestedString, expectedString1);
        assert.equal(result13.matches.length, 1);

        assert.equal(result14.originalString, testString14);
        assert.equal(result14.suggestedString, expectedString1);
        assert.equal(result14.matches.length, 1);

        assert.equal(result15.originalString, testString15);
        assert.equal(result15.suggestedString, expectedString1);
        assert.equal(result15.matches.length, 2);

        assert.equal(result16.originalString, testString16);
        assert.equal(result16.suggestedString, expectedString1);
        assert.equal(result16.matches.length, 1);

        assert.equal(result17.originalString, testString17);
        assert.equal(result17.suggestedString, expectedString1);
        assert.equal(result17.matches.length, 1);

        assert.equal(result18.originalString, testString18);
        assert.equal(result18.suggestedString, expectedString3);
        assert.equal(result18.matches.length, 1);

        assert.equal(result19.originalString, testString19);
        assert.equal(result19.suggestedString, expectedString1);
        assert.equal(result19.matches.length, 1);

        assert.equal(result20.originalString, testString20);
        assert.equal(result20.suggestedString, expectedString1);
        assert.equal(result20.matches.length, 1);

        assert.equal(result21.originalString, testString21);
        assert.equal(result21.suggestedString, expectedString1);
        assert.equal(result21.matches.length, 1);

        assert.equal(result22.originalString, testString22);
        assert.equal(result22.suggestedString, expectedString4);
        assert.equal(result22.matches.length, 1);

        assert.equal(result23.originalString, testString23);
        assert.equal(result23.suggestedString, expectedString1);
        assert.equal(result23.matches.length, 2);

        assert.equal(result24.originalString, testString24);
        assert.equal(result24.suggestedString, expectedString5);
        assert.equal(result24.matches.length, 1);

        assert.equal(result25.originalString, testString25);
        assert.equal(result25.suggestedString, expectedString1);
        assert.equal(result25.matches.length, 1);

        assert.equal(result26.originalString, testString26);
        assert.equal(result26.suggestedString, expectedString1);
        assert.equal(result26.matches.length, 1);

        assert.equal(result27.originalString, testString27);
        assert.equal(result27.suggestedString, expectedString1);
        assert.equal(result27.matches.length, 1);
    })
});
