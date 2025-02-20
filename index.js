const htmlSvgReg = /<(?:".*?""*?|'.*?''*?|[^<]*?)*>/gisv;

const findHTMLSVG = (str) => {
    const res1 = str.match(htmlSvgReg);
    return [htmlSvgReg.test(str), res1];
}

export default findHTMLSVG;
