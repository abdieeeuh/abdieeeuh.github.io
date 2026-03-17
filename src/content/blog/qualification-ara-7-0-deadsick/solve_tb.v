`timescale 1ns/1ps
`default_nettype none

module solve_tb;
  // Simple clock generator.
  reg clk = 0;
  always #10 clk = ~clk;

  // DUT I/O.
  reg rst_n;
  reg  [7:0] data_in;
  reg        data_valid;
  wire       tx_pin;

  vault_challenge_top dut (
    .clk(clk),
    .rst_n(rst_n),
    .data_in(data_in),
    .data_valid(data_valid),
    .tx_pin(tx_pin)
  );

  // Captured bytes bookkeeping:
  // - `got` counts every tx_start pulse, including the first padding byte.
  // - `printed` counts only the actual printed flag bytes.
  integer got;
  integer printed;
  integer cycles;
  reg [7:0] out_bytes [0:255];

  // Edge detector for tx_start so we only capture once per transmitted byte.
  reg prev_tx_fire;

  // Drive one byte as a clean 1-cycle valid pulse.
  task automatic pulse_byte(input [7:0] b);
    begin
      @(negedge clk);
      data_in = b;
      data_valid = 1'b1;
      @(negedge clk);
      data_valid = 1'b0;
      data_in = 8'h00;
    end
  endtask

  initial begin
    // Reset and initialize.
    rst_n = 1'b0;
    data_in = 8'h00;
    data_valid = 1'b0;
    got = 0;
    printed = 0;
    cycles = 0;
    prev_tx_fire = 1'b0;

    repeat (5) @(posedge clk);
    rst_n = 1'b1;

    // Stage 1: unlock vm_enable via key_validator.
    pulse_byte(8'h4B); // K
    pulse_byte(8'h45); // E
    pulse_byte(8'h59); // Y
    pulse_byte(8'hF1); // final unlock byte

    // Stage 2: unlock the VM core.
    pulse_byte(8'h1D);
    pulse_byte(8'h1E);
    pulse_byte(8'h1A);
    pulse_byte(8'h1B);
    pulse_byte(8'h00);
    pulse_byte(8'h00);
    pulse_byte(8'h00);
    pulse_byte(8'h00);

    // One padding byte is emitted first, then the 77-byte flag payload.
    while (printed < 77 && cycles < 5_000_000) begin
      @(posedge clk);
    end

    if (printed < 77) begin
      $display("\n[!] Timeout: printed=%0d got=%0d vm_enable=%0d vm_unlock=%0d window_open=%0d tx_en=%0d byte_cnt=%0d",
               printed, got, dut.vm_enable, dut.vm_unlock, dut.window_open, dut.tx_en, dut.vault.byte_count);
    end else begin
      $write("\n");
    end
    $finish;
  end

  always @(posedge clk) begin
    cycles <= cycles + 1;

    prev_tx_fire <= dut.tx_fire;
    if (dut.tx_fire && !prev_tx_fire) begin
      // Each tx_fire corresponds to a new byte being queued into the UART.
      got = got + 1;
      if (got != 1) begin
        // Skip the first byte: it is a deliberate padding byte.
        out_bytes[printed] = dut.artifact_data;
        $write("%c", dut.artifact_data);
        printed = printed + 1;
      end
    end
  end

endmodule
