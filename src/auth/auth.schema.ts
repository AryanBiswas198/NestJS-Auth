import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";

@Schema()
export class User extends Document {
    @Prop({required: true})
    firstName: string;

    @Prop({required: true})
    lastName: string;

    @Prop({required: true, unique: true})
    email: string;

    @Prop({required: true})
    password: string;

    @Prop({default: false})
    isVerified: boolean;

    @Prop()
    verifyToken: string;

    @Prop()
    verifyTokenExpiry: Date;

    @Prop()
    forgotPasswordToken: string;

    @Prop()
    forgotPasswordTokenExpiry: string;
}

export const UserSchema = SchemaFactory.createForClass(User);