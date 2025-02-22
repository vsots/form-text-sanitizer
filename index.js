const openAngleBracket = /<|%3C|&lt;?|&#0{0,6}60;?|&#x0{0,6}3c;?/gisv;
const closedAngleBracket = />|%3e|&gt;?|&#0{0,6}62;?|&#x0{0,6}3e;?/gisv;
const doubleQuote = /"|%22|&quot;?|&#0{0,6}34;?|&#x0{0,6}22;?/gisv;
const singleQuote = /'|%27|&apos;?|&#0{0,6}39;?|&#x0{0,6}27;?/gisv;
const backtick = /`|%60|&DiacriticalGrave;?|&#0{0,6}96;?|&#x0{0,6}60;?/gisv;
const htmlSvgReg = /<(?:".*?""*?|'.*?''*?|`.*?``*?|[^<]*?)*>?/gisv;

const findHTMLSVG = (str) => {
    const res1 = str.match(htmlSvgReg);
    const test = htmlSvgReg.test(str);

    return [test, res1];
}


export default findHTMLSVG;
