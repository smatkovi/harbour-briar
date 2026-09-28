import QtQuick 2.0
import Amber.QrFilter 1.0

// Der Leser der Kamera-App, in unserem Sucher.
//
// `Amber.QrFilter` ist ein QAbstractVideoFilter: er haengt in
// VideoOutput.filters und bekommt jedes Sucherbild, das ohnehin schon da ist.
// Dahinter steht ZXing (libZXing.so.3) -- derselbe Leser, den Briar auf
// Android benutzt. Kein Foto, keine Datei, kein Skalieren: deshalb ist die
// Kamera-App so schnell, und deshalb sind wir es jetzt auch.
//
// Diese Datei steht absichtlich allein. Der Import oben gibt es nur, wo das
// Paket qr-filter-qml-plugin liegt; stuende er in ScanPage.qml, liesse sich
// die ganze Seite auf einem Sailfish ohne das Paket nicht mehr laden. So
// probiert ScanPage sie mit Qt.createComponent und faellt sauber auf den
// alten Weg (Foto + quirc) zurueck, wenn sie fehlt.
QrFilter {
}
