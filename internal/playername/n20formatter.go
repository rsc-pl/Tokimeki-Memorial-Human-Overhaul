package playername

// surname formatting: host-side reference contract for the TWO original N20 surname-only
// formatter sources identified by retail previous version/previous version and the owner previous version trace.
// This does not modify MIPS, RAM, a CUE, the private source, or text records.
// The actual renderer and destination lifetime remain unproven.
import (
	"bytes"
	"errors"
	"fmt"
	"tokimemo/internal/script"
)

const (
	PS1FormatterSurnameReturnA uint32 = 0x8007f8a0
	PS1FormatterSurnameReturnB uint32 = 0x80080c38
)

type FormatterSurname struct {
	Schema                              int    `json:"schema"`
	Status                              string `json:"status"`
	CallerReturn                        string `json:"caller_return"`
	OriginalCP932Bytes                  int    `json:"original_cp932_bytes"`
	FormattedInputBytes                 int    `json:"formatted_input_bytes_including_nul"`
	PairOutputBytes                     int    `json:"pair_output_bytes_including_nul"`
	PairOutputCells                     int    `json:"pair_output_cells"`
	NeedsIndependentScratch             bool   `json:"needs_independently_owned_scratch"`
	GlobalCopyVerifiedAgainstSavedField bool   `json:"global_copy_equals_saved_surname"`
	FormatterVerifiedAgainstGlobalCopy  bool   `json:"formatted_source_equals_surname_ascii_space"`
	OriginalInputsUntouched             bool   `json:"original_inputs_untouched"`
	ProducerAndConsumerOwnershipProven  bool   `json:"producer_and_consumer_ownership_proven"`
	Installed                           bool   `json:"installed"`
	SafeToPatch                         bool   `json:"safe_to_patch"`
	PairBytes                           []byte `json:"-"`
}

// PreparePS1FormatterSurname builds only an atomic output candidate for
// a very specific original `sprintf(sp+0x68, "%s ", 0x800CA16C)` route.
// The caller must independently prove guest output scratch lifetime and
// source/consumer semantics; a matching RA or 'capacity' number cannot do it.
// It refuses messages with honorifics, full names, leading/trailing text,
// multiple tokens or unrecognized character boundaries. No time-based joins.
func PreparePS1FormatterSurname(returnAddress uint32, savedField, globalCopy, formattedInput []byte, hypotheticalCapacity int) (FormatterSurname, error) {
	r := FormatterSurname{Schema: 1, Status: "no_write", OriginalInputsUntouched: true, NeedsIndependentScratch: true}
	switch returnAddress {
	case PS1FormatterSurnameReturnA:
		r.CallerReturn = "0x8007f8a0"
	case PS1FormatterSurnameReturnB:
		r.CallerReturn = "0x80080c38"
	default:
		return r, errors.New("not one of the two witnessed original surname formatter returns")
	}
	if len(savedField) < 3 || len(savedField) > 7 || savedField[len(savedField)-1] != 0 || bytes.IndexByte(savedField[:len(savedField)-1], 0) >= 0 || (len(savedField)-1)%2 != 0 {
		return r, errors.New("saved surname not exactly 1..3 CP932 units plus NUL")
	}
	raw := savedField[:len(savedField)-1]
	if len(globalCopy) < len(savedField) || len(globalCopy) > 8 || !bytes.Equal(globalCopy[:len(savedField)], savedField) {
		return r, errors.New("0x800CA16C global copy not established to match current saved surname")
	}
	for _, b := range globalCopy[len(savedField):] {
		if b != 0 {
			return r, errors.New("unverified trailing global bytes")
		}
	}
	r.GlobalCopyVerifiedAgainstSavedField = true
	// The retail template is '%s ' (one ASCII 0x20), not a CP932 0x8140 space.
	want := append(bytes.Clone(raw), 0x20, 0)
	if !bytes.Equal(formattedInput, want) {
		return r, fmt.Errorf("not the exact retail %%s plus ASCII space input")
	}
	r.FormatterVerifiedAgainstGlobalCopy = true
	r.OriginalCP932Bytes = len(raw)
	r.FormattedInputBytes = len(want)
	kana, err := DecodeCP932Kana(raw)
	if err != nil {
		return r, fmt.Errorf("unsupported CP932 saved surname: %w", err)
	}
	if len([]rune(kana)) < 1 || len([]rune(kana)) > 3 {
		return r, errors.New("wrong kana count")
	}
	for _, ch := range kana {
		if !((ch >= 'ぁ' && ch <= 'ゖ') || (ch >= 'ァ' && ch <= 'ヶ') || ch == 'ー') {
			return r, errors.New("surname contains non-kana")
		}
	}
	latin, err := RomanizeKana(kana)
	if err != nil {
		return r, err
	}
	var encoder script.PairEncoder
	pair, err := encoder.Encode(latin + " ")
	if err != nil || !encoder.Used {
		return r, errors.New("unsupported pairfont surname")
	}
	if hypotheticalCapacity < 1 || hypotheticalCapacity > 64 || len(pair)+1 > hypotheticalCapacity {
		return r, errors.New("unverified or too small hypothetical scratch capacity")
	}
	r.PairBytes = append(pair, 0)
	r.PairOutputBytes = len(r.PairBytes)
	r.PairOutputCells = len(pair) / 2
	r.Status = "host_candidate_only_requires_producer_consumer_and_guest_scratch_proof"
	return r, nil
}
