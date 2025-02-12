const findHTML = (str) => {
    const regex = /(<script.*?>|<\/script.*?>|javascript:|<svg.*?>|alert\(|<a.*?>|<\/a.*?>)/sivg;
    return [regex.test(str), str.match(regex)];
}

export default findHTML;
