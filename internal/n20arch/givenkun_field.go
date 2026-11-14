package n20arch

// The relocated dynamic P field accommodates any valid three-kana saved
// given/surname with an attested -kun or -san suffix and a font pad/NUL.
// The retail selector writer initializes it before N6-FP conversion.
const givenKunExtended uint32 = 0x8012b520
