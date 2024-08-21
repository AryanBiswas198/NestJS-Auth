import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User } from "./auth.schema";
import { Model } from "mongoose";
import * as bcrypt from "bcrypt";
import * as nodemailer from "nodemailer"


@Injectable()
export class MailerService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) {}

    async sendEmail({email, emailType, userId}: {email: string, emailType: string, userId: any}): Promise<void> {

        const hashedToken = await bcrypt.hash(userId.toString(), 10);

        if(emailType === 'VERIFY'){
            await this.userModel.findByIdAndUpdate(userId, {
                verifyToken: hashedToken,
                verifyTokenExpiry: new Date(Date.now() + 3600000),
            });
        }
        // Add else part later

        const transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            auth: {
              user: process.env.MAIL_USER,
              pass: process.env.MAIL_PASS,
            },
          });
      
          const mailOptions = {
            from: 'aryanb198@example.com',
            to: email,
            subject: emailType === 'VERIFY' ? 'Verify your Email' : 'Reset your Password',
            html: `<p>Click <a href="${process.env.DOMAIN}/verifyemail?token=${hashedToken}">here</a> to ${emailType === 'VERIFY' ? 'verify your email' : 'reset your password'}</p>`,
          };
      
          await transporter.sendMail(mailOptions);
    }
}