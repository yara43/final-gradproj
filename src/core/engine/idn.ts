/** Decode an RFC 3492 Punycode label without Node-only APIs. */
function decodeLabel(label: string): string {
  if (!label.startsWith('xn--')) return label;
  const input = label.slice(4);
  const output: number[] = [];
  const delimiter = input.lastIndexOf('-');
  let position = delimiter >= 0 ? delimiter + 1 : 0;
  if (delimiter >= 0) {
    for (let index = 0; index < delimiter; index++) output.push(input.charCodeAt(index));
  }

  let codePoint = 128;
  let offset = 0;
  let bias = 72;
  const digit = (character: string): number => {
    const code = character.charCodeAt(0);
    if (code >= 48 && code <= 57) return code - 22;
    if (code >= 65 && code <= 90) return code - 65;
    if (code >= 97 && code <= 122) return code - 97;
    throw new Error('Invalid Punycode digit');
  };
  const adapt = (delta: number, points: number, first: boolean): number => {
    delta = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
    delta += Math.floor(delta / points);
    let nextBias = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      nextBias += 36;
    }
    return nextBias + Math.floor((36 * delta) / (delta + 38));
  };

  while (position < input.length) {
    const previousOffset = offset;
    let multiplier = 1;
    for (let base = 36; ; base += 36) {
      if (position >= input.length) throw new Error('Truncated Punycode label');
      const value = digit(input[position++]);
      offset += value * multiplier;
      const threshold = base <= bias ? 1 : base >= bias + 26 ? 26 : base - bias;
      if (value < threshold) break;
      multiplier *= 36 - threshold;
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(multiplier)) throw new Error('Punycode overflow');
    }
    const points = output.length + 1;
    bias = adapt(offset - previousOffset, points, previousOffset === 0);
    codePoint += Math.floor(offset / points);
    offset %= points;
    if (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) throw new Error('Invalid Unicode code point');
    output.splice(offset++, 0, codePoint);
  }
  return String.fromCodePoint(...output);
}

export function decodePunycodeHostname(hostname: string): string {
  return hostname.split('.').map(label => {
    try { return decodeLabel(label); } catch { return label; }
  }).join('.');
}
