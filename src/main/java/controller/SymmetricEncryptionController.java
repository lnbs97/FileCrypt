package controller;

import controller.enums.Status;
import encryption.*;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;
import encryption.interfaces.SymmetricalEncryptor;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.net.URL;
import java.util.ResourceBundle;

/**
 * Controller for the symmetric_encryption.fxml layout
 * Controls UI elements and triggers actions in the {@link SymmetricEncryption} class
 *
 * @author Leo Nobis
 */
@SuppressWarnings("ALL")
public class SymmetricEncryptionController implements Initializable {

    enum Mode {
        ENCRYPT,
        DECRYPT
    }

    // File to be encrypted
    private File selectedFile;
    // File holding configuration information
    private File configurationFile;

    private Mode mode = Mode.ENCRYPT;

    private boolean isFileSelected = false;
    private boolean isConfigSelected = false;
    private boolean isAlgorithmSelected = false;

    // UI Elements
    public Label selectedFileLabel;
    public Label configurationFileLabel;
    public Label statusLabel;
    public Label encryptLabel;
    public ChoiceBox<SymmetricalEncryptor> cipherChoiceBox;
    public ChoiceBox<PaddingMode> paddingModeChoiceBox;
    public ChoiceBox<BlockMode> blockModeChoiceBox;
    public ChoiceBox<Integer> keyLengthChoiceBox;
    public ToggleGroup modeSelectionToggleGroup;
    public HBox decryptConfigurationHbox;
    public Button encryptButton;

    private final SymmetricalEncryptor[] algorithms = {new SymmetricEncryption()};
    private SymmetricalEncryptor selectedAlgorithm;

    public void onEncryptSelected() {
        mode = Mode.ENCRYPT;
        updateStatus();
        decryptConfigurationHbox.setVisible(false);
        encryptButton.setText("Encrypt");
        encryptLabel.setText("4. Start encryption");
    }

    public void onDecryptSelected() {
        mode = Mode.DECRYPT;
        updateStatus();
        decryptConfigurationHbox.setVisible(true);
        encryptButton.setText("Decrypt");
        encryptLabel.setText("4. Start decryption");
    }

    public void encryptClicked(ActionEvent actionEvent) throws Exception {
        if (updateStatus()) {
            selectedAlgorithm.init(
                    paddingModeChoiceBox.getValue(),
                    blockModeChoiceBox.getValue(),
                    keyLengthChoiceBox.getValue(),
                    selectedFile,
                    configurationFile);

            switch (mode) {
                case DECRYPT:
                    try {
                        selectedAlgorithm.decrypt();
                        statusLabel.setText(Status.DECRYPTION_SUCCESSFUL.label);
                    } catch (AEADBadTagException e) {
                        statusLabel.setText(Status.MAC_CHECK_FAILED.label);
                    } catch
                    (Exception e) {
                        statusLabel.setText(Status.DECRYPTION_FAILED.label);
                        throw e;
                    }
                    break;
                case ENCRYPT:
                    try {
                        selectedAlgorithm.encrypt();
                        statusLabel.setText(Status.ENCRYPTION_SUCCESSFUL.label);
                    } catch (IllegalBlockSizeException e) {
                        statusLabel.setText(Status.ILLEGAL_BLOCKSIZE.label);
                    } catch (NoSuchPaddingException e) {
                        statusLabel.setText(Status.NO_SUCH_PADDING.label);
                    } catch (Exception e) {
                        statusLabel.setText(Status.ENCRYPTION_FAILED.label);
                        throw e;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    public void browseClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        selectedFile = fileChooser.showOpenDialog(null);
        if (selectedFile != null) {
            selectedFileLabel.setText(selectedFile.getAbsolutePath());
            isFileSelected = true;
            updateStatus();
        } else {
            selectedFileLabel.setText("No file selected");
            isFileSelected = false;
            updateStatus();
        }
    }

    public void browseConfigurationClicked(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        configurationFile = fileChooser.showOpenDialog(null);
        if (configurationFile != null) {
            isConfigSelected = true;
            updateStatus();
            configurationFileLabel.setText(configurationFile.getAbsolutePath());
        } else {
            configurationFileLabel.setText("No configuration file selected");
            isConfigSelected = false;
            updateStatus();
        }
    }

    private boolean updateStatus() {
        if (isFileSelected) {
            if (mode == Mode.DECRYPT) {
                if (isConfigSelected) {
                    if (isAlgorithmSelected) {
                        statusLabel.setText(Status.READY.label);
                        return true;
                    } else {
                        statusLabel.setText(Status.SELECT_ALGORITHM.label);
                    }
                } else {
                    statusLabel.setText(Status.SELECT_CONFIG.label);
                }
            } else if (mode == Mode.ENCRYPT) {
                if (isAlgorithmSelected) {
                    statusLabel.setText(Status.READY.label);
                    return true;
                } else {
                    statusLabel.setText(Status.SELECT_ALGORITHM.label);
                }
            }
        } else {
            statusLabel.setText(Status.SELECT_FILE.label);
        }
        return false;
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        updateStatus();

        decryptConfigurationHbox.setVisible(false);
        cipherChoiceBox.getItems().addAll(algorithms);
        cipherChoiceBox.setOnAction(actionEvent -> {
            selectedAlgorithm = cipherChoiceBox.getSelectionModel().getSelectedItem();
            isAlgorithmSelected = true;
            updateStatus();

            paddingModeChoiceBox.setValue(selectedAlgorithm.getSupportedPaddingModes()[0]);
            paddingModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedPaddingModes()));

            blockModeChoiceBox.setValue(selectedAlgorithm.getSupportedBlockModes()[0]);
            blockModeChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedBlockModes()));

            keyLengthChoiceBox.setValue(selectedAlgorithm.getSupportedKeyLengths()[0]);
            keyLengthChoiceBox.setItems(FXCollections.observableArrayList(selectedAlgorithm.getSupportedKeyLengths()));
        });
    }
}
