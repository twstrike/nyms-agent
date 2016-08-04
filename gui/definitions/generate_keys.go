package definitions

func init() {
	add(`GenerateKeys`, &defGenerateKeys{})
}

type defGenerateKeys struct{}

func (*defGenerateKeys) String() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<interface>
  <requires lib="gtk+" version="2.24"/>
  <!-- interface-naming-policy project-wide -->
  <object class="GtkDialog" id="generateDialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkVBox" id="dialog-vbox1">
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <property name="spacing">2</property>
        <child>
          <object class="GtkLabel" id="somelabel">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="label" translatable="yes">email</property>
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkEntry" id="email-entry">
            <property name="visible">True</property>
            <property name="can_focus">True</property>
            <property name="max_length">255</property>
            <property name="placeholder-text">email@example.com</property>
            <property name="primary_icon_activatable">False</property>
            <property name="secondary_icon_activatable">False</property>
            <property name="primary_icon_sensitive">True</property>
            <property name="secondary_icon_sensitive">True</property>
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child>
          <object class="GtkEntry" id="real-name-entry">
            <property name="visible">True</property>
            <property name="can_focus">True</property>
            <property name="max_length">255</property>
            <property name="placeholder-text">RealName</property>
            <property name="primary_icon_activatable">False</property>
            <property name="secondary_icon_activatable">False</property>
            <property name="primary_icon_sensitive">True</property>
            <property name="secondary_icon_sensitive">True</property>
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child internal-child="action_area">
          <object class="GtkHButtonBox" id="button_box">
            <property name="orientation">GTK_ORIENTATION_HORIZONTAL</property>
            <property name="margin-top">10</property>
            <child>
              <object class="GtkButton" id="button_cancel">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="label" translatable="yes">Cancel</property>
              </object>
              <packing>
                  <property name="expand">True</property>
                  <property name="fill">True</property>
                  <property name="position">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button_ok">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="label" translatable="yes">Generate</property>
                <property name="can-default">true</property>
              </object>
              <packing>
                  <property name="expand">True</property>
                  <property name="fill">True</property>
                  <property name="position">1</property>
              </packing>
            </child>
          </object>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="cancel">button_cancel</action-widget>
      <action-widget response="ok" default="true">button_ok</action-widget>
    </action-widgets>
  </object>
</interface>
`
}
