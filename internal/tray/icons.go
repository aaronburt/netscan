package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"

	"github.com/aaronburt/netscan/internal/detector"
)

func GenerateIcon(state detector.State) []byte {
	size := 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	var fillColor, borderColor color.RGBA
	switch state {
	case detector.StateHealthy:
		fillColor = color.RGBA{R: 16, G: 185, B: 129, A: 255}
		borderColor = color.RGBA{R: 5, G: 150, B: 105, A: 255}
	case detector.StateDegraded:
		fillColor = color.RGBA{R: 245, G: 158, B: 11, A: 255}
		borderColor = color.RGBA{R: 217, G: 119, B: 6, A: 255}
	case detector.StateOutage, detector.StateRecovering:
		fillColor = color.RGBA{R: 239, G: 68, B: 68, A: 255}
		borderColor = color.RGBA{R: 220, G: 38, B: 38, A: 255}
	default:
		fillColor = color.RGBA{R: 100, G: 116, B: 139, A: 255}
		borderColor = color.RGBA{R: 71, G: 85, B: 105, A: 255}
	}

	cx, cy := float64(size)/2.0, float64(size)/2.0
	outerR := float64(size)/2.0 - 1.5
	innerR := outerR - 2.5

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			dist := dx*dx + dy*dy

			if dist <= innerR*innerR {
				img.Set(x, y, fillColor)
			} else if dist <= outerR*outerR {
				img.Set(x, y, borderColor)
			}
		}
	}

	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	pngBytes := pngBuf.Bytes()

	var icoBuf bytes.Buffer
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint16(1))

	_ = icoBuf.WriteByte(byte(size))
	_ = icoBuf.WriteByte(byte(size))
	_ = icoBuf.WriteByte(0)
	_ = icoBuf.WriteByte(0)
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint16(32))
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint32(len(pngBytes)))
	_ = binary.Write(&icoBuf, binary.LittleEndian, uint32(22))

	icoBuf.Write(pngBytes)
	return icoBuf.Bytes()
}
