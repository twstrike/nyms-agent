package definitions

func init() {
	add(`Main`, &defMain{})
}

type defMain struct{}

func (*defMain) String() string {
	return `<interface>
  <object class="GtkApplicationWindow" id="mainWindow">
    <property name="can_focus">False</property>
    <property name="title">Nyms Keychain</property>
    <property name="default_width">800</property>
    <property name="default_height">600</property>
    <signal name="destroy" handler="on_close_window_signal" swapped="no"/>
    <child>
      <object class="GtkBox" id="Hbox">
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <child>
          <object class="GtkBox" id="Vbox">
            <property name="can_focus">False</property>
            <property name="orientation">vertical</property>
            <child>
              <object class="GtkMenuBar" id="menubar">
                <property name="can_focus">False</property>
                <child>
                  <object class="GtkMenuItem" id="FilesMenu">
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">_Files</property>
                    <property name="use-underline">True</property>
                    <child type="submenu">
                      <object class="GtkMenu" id="Keys">
                        <property name="can_focus">False</property>
                        <child>
                          <object class="GtkMenuItem" id="GenerateKeys">
                            <property name="can_focus">True</property>
                            <property name="label" translatable="yes">Generate New key pair</property>
                            <signal name="activate" handler="on_generate_key_dialog_signal" swapped="no"/>
                          </object>
                        </child>
                      </object>
                    </child>
                  </object>
                </child>
                <child>
                  <object class="GtkMenuItem" id="ViewMenu">
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">_View</property>
                    <property name="use-underline">True</property>
                    <child type="submenu">
                      <object class="GtkMenu" id="menu2">
                        <property name="can_focus">False</property>
                        <child>
                          <object class="GtkCheckMenuItem" id="CheckItemFilterPublic">
                            <property name="can_focus">True</property>
                            <property name="label" translatable="yes">Show Public Keys</property>
                            <signal name="toggled" handler="on_toggled_check_Item_Merge_signal" swapped="no"/>
                          </object>
                        </child>
                        <child>
                          <object class="GtkCheckMenuItem" id="CheckItemFilterPrivate">
                            <property name="can_focus">False</property>
                            <property name="label" translatable="yes">Show Private Keys</property>
                            <signal name="toggled" handler="on_toggled_check_Item_Show_Offline_signal" swapped="no"/>
                          </object>
                        </child>
                      </object>
                    </child>
                  </object>
                </child>
                <child>
                  <object class="GtkMenuItem" id="OptionsMenu">
                    <property name="can-focus">False</property>
                    <property name="label" translatable="yes">_Options</property>
                    <property name="use-underline">True</property>
                    <child type="submenu">
                      <object class="GtkMenu" id="options_submenu">
                        <property name="can_focus">False</property>
                        <child>
                          <object class="GtkCheckMenuItem" id="EncryptConfigurationFileCheckMenuItem">
                            <property name="can_focus">False</property>
                            <property name="label" translatable="yes">Encrypt configuration file</property>
                            <signal name="toggled" handler="on_toggled_encrypt_configuration_file_signal" swapped="no"/>
                          </object>
                        </child>
                        <child>
                          <object class="GtkMenuItem" id="preferencesMenuItem">
                            <property name="can_focus">False</property>
                            <property name="label" translatable="yes">_Preferences...</property>
                            <property name="use-underline">True</property>
                            <signal name="activate" handler="on_preferences_signal" swapped="no"/>
                          </object>
                        </child>
                      </object>
                    </child>
                  </object>
                </child>
                <child>
                  <object class="GtkMenuItem" id="HelpMenu">
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Help</property>
                    <child type="submenu">
                      <object class="GtkMenu" id="Feedback">
                        <property name="can_focus">False</property>
                        <child>
                          <object class="GtkMenuItem" id="feedbackMenu">
                            <property name="can_focus">False</property>
                            <property name="label" translatable="yes">Feedback</property>
                            <signal name="activate" handler="on_feedback_dialog_signal" swapped="no"/>
                          </object>
                        </child>
                        <child>
                          <object class="GtkMenuItem" id="aboutMenu">
                            <property name="can_focus">False</property>
                            <property name="label" translatable="yes">About</property>
                            <signal name="activate" handler="on_about_dialog_signal" swapped="no"/>
                          </object>
                        </child>
                      </object>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkBox" id="notification-area">
                <property name="can_focus">False</property>
                <property name="orientation">vertical</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">False</property>
                <property name="pack_type">end</property>
                <property name="position">0</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">0</property>
          </packing>
        </child>
      </object>
    </child>
  </object>
</interface>
`
}
