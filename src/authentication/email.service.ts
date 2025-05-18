import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  private transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<number>('SMTP_PORT'),
      secure: this.configService.get<string>('SMTP_SECURE') === 'true', // Convert string to boolean
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
      tls: {
        rejectUnauthorized: false, // Optional: Helps with SSL issues
      },
    });

    // Test the SMTP connection
    this.transporter.verify((error, success) => {
      if (error) {
        console.error('❌ SMTP Connection Error:', error);
      } else {
        console.log('✅ SMTP Server is ready to send emails.');
      }
    });
  }

  async sendMail(to: string, subject: string, text: string, html?: string) {
    const mailOptions = {
      from: `"Ateck Project" <${this.configService.get<string>('SMTP_USER')}>`,
      to,
      subject,
      text,
      html,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      console.log('📧 Email sent:', info.messageId);
      return info;
    } catch (error) {
      console.error('❌ Error sending email:', error);
      throw error;
    }
  }

  generateOTP(): string {
    return crypto.randomInt(100000, 999999).toString(); // Secure 6-digit OTP
  }

  async sendOtpEmail(to: string, otp: string) {
    const subject = 'Your One-Time Password (OTP)';
    
    const text = `Hello, Your OTP for your ateck account authentication is: ${otp}`;
    const html = `<p>Your OTP for authentication is: <strong>${otp}</strong></p>`;

    await this.sendMail(to, subject, text, html);
  }
}
