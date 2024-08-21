import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './auth.schema';
import { Model } from 'mongoose';
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { MailerService } from './mailer.service';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { SignupUserDto } from './dto/signup-user.dto';
import { LoginUserDto } from './dto/login-user.dto';


@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async findAll(): Promise<Partial<User>[]> {
    return this.userModel.find({}, '_id firstName lastName email isVerified').exec();
  }

  async findOne(id: string): Promise<User>{
    return this.userModel.findById(id).select("-password").exec();
  }

  async signup(user: SignupUserDto): Promise<User> {
    const existingUser = await this.userModel.findOne({email: user.email});
    if(existingUser){
      throw new Error('User Already Exists');
    }

    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser = new this.userModel({
      ...user,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    // Send Verification Email
    const mailerService = new MailerService(this.userModel);
    await mailerService.sendEmail({email: user.email, emailType: 'VERIFY', userId: savedUser._id});

    const userWithoutSensitiveData = await this.userModel.findById(savedUser._id).select("-password").exec();

    return userWithoutSensitiveData.toObject();
  }


  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<{success: boolean; message: string}> {
    const {token} = verifyEmailDto;
    const user = await this.userModel.findOne({
      verifyToken: token,
      verifyTokenExpiry: {$gt: new Date()},
    });

    if(!user){
      throw new NotFoundException('Invalid or Expired Token !!');
    }

    user.isVerified = true;
    user.verifyToken = "";
    user.verifyTokenExpiry = null;

    await user.save();
    return {
      success: true,
      message: 'Email Verified Successfully',
    };
  }
  
  async login(user: LoginUserDto): Promise<{token: String}> {
    const existingUser = await this.userModel.findOne({email: user.email});
    if(!existingUser){
      throw new UnauthorizedException('User does not Exists !!');
    }

    const validPassword = await bcrypt.compare(user.password, existingUser.password);
    if(!validPassword){
      throw new UnauthorizedException('Invalid Password, Please Try Again');
    }

    const payload = {id: existingUser._id, email: existingUser.email};
    const token = jwt.sign(payload, process.env.TOKEN_SECRET, {
      expiresIn: '1d',
    });

    return {token};
  }


  async updateUser(id: string, user: UpdateUserDto): Promise<User> {
    const updatedUser =  this.userModel.findByIdAndUpdate(id, {
      $set: {
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    }, {new: true}).select("-password").exec();

    if(!updatedUser){
      throw new Error("User Not Found !!");
    }

    return updatedUser;
  }


  async deleteOne(id: string): Promise<any> {
    const user = this.userModel.findByIdAndDelete(id).exec();

    if(!user){
      throw new Error("User Not Found !!");
    }
    return {
      success: true,
      message: "User Deleted Successfully",
    };
  }
}
