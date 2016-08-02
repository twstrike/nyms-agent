package definitions

func init() {
	add(`KeyRingTable`, &defKeyRingTable{})
}

type defKeyRingTable struct{}

func (*defKeyRingTable) String() string {
	return `<interface>
  <object class="GtkGrid" id="keyRingTable">
  </object>
</interface>
`
}
