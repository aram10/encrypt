import org.jetbrains.annotations.Contract;

import java.security.InvalidParameterException;
import java.util.*;
import java.util.stream.IntStream;
import org.javatuples.Pair;


public class Encrypt
{

    private static final String GETTYSBURG = "FOURSCOREANDSEVENYEARSAGOOURFATHERSBROUGHTFORTHONTHISCONTINENTANEWNATI" +
            "ONCONCEIVEDINLIBERTYANDDEDICATEDTOTHEPROPOSITIONTHATALLMENARECREATEDEQUAL";

    /**
     * Don't let anyone instantiate this class.
     */
    private Encrypt() {}

    /**
     * Computes the Atbash Cipher, a special case of the Affine Cipher.
     * @param str plaintext to encrypt
     * @return encrypted text
     */
    public static String atbash(String str)
    {
        str = Encrypt.format(str, true);
        StringBuilder encrypted = new StringBuilder("");
        for(int i = 0; i < str.length(); i++)
        {
            char ch = str.charAt(i);
            if(ch == ' ')
            {
                encrypted.append(ch);
            }
            else
            {
                int num = 25 - ((ch - 65));
                char ch1 = (char) (65 + num);
                encrypted.append(ch1);
            }
        }
        return encrypted.toString();
    }

    /**
     * Computer the Caesar Cipher, a monoalphabetic substitution cipher where each letter is replaced by a character
     * shifted by a certain amount.
     * @param str plaintext to encrypt
     * @param offset amount of shifting
     * @return encrypted text
     */
    public static String caesar(String str, int offset)
    {
        offset = offset % 26;
        str = Encrypt.format(str, true);
        StringBuilder encrypted = new StringBuilder("");
        for(int i = 0; i < str.length(); i++)
        {
            char ch = str.charAt(i);
            if(ch == ' ')
            {
                encrypted.append(ch);
            }
            else
            {
                int num = ch + offset;
                if(num > 90)
                {
                    num = num - 26;
                }
                char ch1 = (char) num;
                encrypted.append(ch1);
            }
        }
        return encrypted.toString();
    }

    /**
     * Computes the Affine Cipher, which encrypts characters by the formula (ax + b) mod m, where a and b are coprime
     * integers and m is the size of the alphabet.
     * @param str plaintext to encrypt
     * @param a
     * @param b
     * @return encrypted text
     */
    public static String affine(String str, int a, int b)
    {
        if(a == 1 || a == 3 || a == 5 || a == 7 || a == 9 || a == 11 || a == 15 || a == 17
                || a == 19 || a == 21 || a == 23 || a == 25)
        {
            StringBuilder sb = new StringBuilder("");
            str = Encrypt.format(str, true);
            for(int i = 0; i < str.length(); i++)
            {
                char ch = str.charAt(i);
                if(ch == ' ')
                {
                    sb.append(ch);
                }
                else
                {
                    int num = ch - 65;
                    int result = ((a * num) + b) % 26;
                    result = 65 + result;
                    char ch1 = (char) result;
                    sb.append(ch1);
                }
            }
            return sb.toString();
        }
        else return null;
    }

    /**
     * Computes the Vigenère Cipher, which is a form of polyalphabetic substitution where the used alphabet for a
     * character depends on a repeating keyword.
     * @param str plaintext to be encrypted
     * @param key keyword for substitution
     * @return encrypted text
     */
    private static String vigenere(String str, String key)
    {
        str = Encrypt.format(str, true);
        key = Encrypt.format(key, false);
        IntStream intStream = key.chars();
        PrimitiveIterator.OfInt chs = intStream.iterator();
        StringBuilder moreKey = new StringBuilder("");
        for(int i = 0; i < str.length(); i++)
        {
            char ch = str.charAt(i);
            if(ch == ' ')
            {
                moreKey.append(' ');
            }
            else
            {
                if(!chs.hasNext())
                {
                    intStream = key.chars();
                    chs = intStream.iterator();
                }
                moreKey.append((char)((int)chs.next()));
            }
        }
        StringBuilder sb = new StringBuilder("");
        for(int i = 0; i < moreKey.length(); i++)
        {
            int a = str.charAt(i);
            int b = moreKey.charAt(i);
            if(a == 32)
            {
                sb.append(' ');
            }
            else
            {
                int result = ((a - 65) + (b - 65)) % 26;
                char ch =  (char) (result + 65);
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    /**
     * Computes the Rail Fence Cipher, a transposition cipher which writes plaintext in a "zigzag" pattern downwards
     * and diagonally on successive "rails" of an imaginary fence.
     * @param str plaintext to be encrypted
     * @param num number of rails
     * @return encrypted text
     */
    private static String railfence(String str, int num)
    {
        str = Encrypt.format(str, true);
        char[][] rails = new char[num][str.length()];
        boolean down = true;
        int i = 0;
        int j = 0;
        while(j < str.length())
        {
            rails[i][j] = str.charAt(j);
            if(down)
            {
                if(i + 1 >= num)
                {
                    down = false;
                    i--;
                }
                else
                {
                    i++;
                }
            }
            else
            {
                if(i <= 0)
                {
                    down = true;
                    i++;
                }
                else
                {
                    i--;
                }
            }
            j++;
        }
        StringBuilder sb = new StringBuilder("");
        for(int k = 0; k < rails.length; k++)
        {
            for(int l = 0; l < rails[k].length; l++)
            {
                char c = rails[k][l];
                if(c != Character.MIN_VALUE)
                {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Computes the Autokey Cipher, a polyalphabetic substitution cipher similar to the Vigenère Cipher, except that
     * the encryption alphabet is composed of the key followed by the plaintext characters.
     * @param str plaintext to be encrypted
     * @param key keyword for substitution
     * @return encrypted text
     */
    private static String autokey(String str, String key)
    {
        str = Encrypt.format(str, false);
        key = Encrypt.format(key, false);
        if(key.length() > str.length())
        {
            throw new InvalidParameterException("Plaintext must be longer than key.");
        }
        StringBuilder moreKey = new StringBuilder(key);
        IntStream intStream = str.chars();
        PrimitiveIterator.OfInt chs = intStream.iterator();
        while(moreKey.length() < str.length())
        {
            if(!chs.hasNext())
            {
                intStream = str.chars();
                chs = intStream.iterator();
            }
            char c = (char)((int)chs.next());
            if(c == ' ')
            {
                throw new InvalidParameterException("Plaintext may not contain spaces.");
            }
            moreKey.append(c);
        }
        StringBuilder sb = new StringBuilder("");
        for(int i = 0; i < moreKey.length(); i++)
        {
            int a = str.charAt(i);
            int b = moreKey.charAt(i);
            if(a == 32)
            {
                sb.append(' ');
            }
            else
            {
                int result = ((a - 65) + (b - 65)) % 26;
                char ch =  (char) (result + 65);
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static String playfair(String str, String key)
    {
        HashMap<Character, Pair<Integer, Integer>> locations = new HashMap<Character, Pair<Integer, Integer>>();
        HashMap<Pair<Integer, Integer>, Character> characters = new HashMap<Pair<Integer, Integer>, Character>();
        str = Encrypt.format(str, false);
        key = Encrypt.format(key, false);
        int i = 0;
        int j = 0;
        PriorityQueue<Integer> letters = new PriorityQueue<Integer>(26);
        for(int k = 65; k < 91; k++)
        {
            //playfair treats i and j as the same character
            if(k != 74)
            {
                letters.add(k);
            }
        }
        for(int k = 0; k < key.length(); k++)
        {
            int c = key.charAt(k);
            if(letters.contains(c))
            {
                locations.put((char) c, new Pair<Integer, Integer>(i, j));
                characters.put(new Pair<Integer, Integer>(i, j), (char) c);
                letters.remove(c);
                if(j == 4)
                {
                    i++;
                    j = 0;
                }
                else
                {
                    j++;
                }
            }
        }
        while(!letters.isEmpty())
        {
            locations.put((char) (int) letters.peek(), new Pair<Integer, Integer>(i, j));
            characters.put(new Pair<Integer, Integer>(i, j), (char) (int) letters.poll());
            if(j == 4)
            {
                i++;
                j = 0;
            }
            else
            {
                j++;
            }
        }
        StringBuilder temp = new StringBuilder("");
        while(str.length() > 1)
        {
            char c1 = str.charAt(0);
            str = str.substring(1, str.length());
            char c2 = str.charAt(0);
            str = str.substring(1, str.length());
            temp.append(c1);
            if(c1 == c2)
            {
                temp.append('X');
            }
            temp.append(c2);
        }
        if(str.length() == 1)
        {
            temp.append(str.charAt(0));
        }
        if(temp.length() % 2 != 0)
        {
            temp.append('X');
        }
        StringBuilder sb = new StringBuilder("");
        while(temp.length() > 0)
        {
            char c0 = temp.charAt(0);
            temp.delete(0, 1);
            char c1 = temp.charAt(0);
            temp.delete(0, 1);
            Pair<Integer, Integer> p0 = locations.get(c0);
            Pair<Integer, Integer> p1 = locations.get(c1);
            //characters on same row
            if(p0.getValue0() == p1.getValue0())
            {
                int r0 = p0.getValue0();
                int cl0 = p0.getValue1() + 1;
                int r1 = p1.getValue0();
                int cl1 = p1.getValue1() + 1;
                //wrap back around table
                if(cl0 > 4)
                {
                    cl0 = 0;
                }
                if(cl1 > 4)
                {
                    cl1 = 0;
                }
                char c2 = characters.get(new Pair<Integer, Integer>(r0, cl0));
                char c3 = characters.get(new Pair<Integer, Integer>(r1, cl1));
                sb.append(c2);
                sb.append(c3);
            }
            else if(p0.getValue1() == p1.getValue1())
            {
                int r0 = p0.getValue0() + 1;
                int cl0 = p0.getValue1();
                int r1 = p1.getValue0() + 1;
                int cl1 = p1.getValue1();
                //wrap back around table
                if(r0 > 4)
                {
                    r0 = 0;
                }
                if(r1 > 4)
                {
                    r1 = 0;
                }
                char c2 = characters.get(new Pair<Integer, Integer>(r0, cl0));
                char c3 = characters.get(new Pair<Integer, Integer>(r1, cl1));
                sb.append(c2);
                sb.append(c3);
            }
            else
            {
                int r0 = p0.getValue0();
                int cl0 = p1.getValue1();
                int r1 = p1.getValue0();
                int cl1 = p0.getValue1();
                char c2 = characters.get(new Pair<Integer, Integer>(r0, cl0));
                char c3 = characters.get(new Pair<Integer, Integer>(r1, cl1));
                sb.append(c2);
                sb.append(c3);
            }

        }
        return sb.toString();
    }

    /**
     *
     * @param str: plaintext
     * @return formatted string
     */
    private static String format(String str, boolean keepWhitespace)
    {
        StringBuilder sb = new StringBuilder("");
        String temp = str.strip();
        for(int i = 0; i < temp.length(); i++)
        {
            char ch = temp.charAt(i);
            if(Character.isLetter(ch) || (Character.isWhitespace(ch) && keepWhitespace))
            {
                sb.append(ch);
            }
        }
        return sb.toString().toUpperCase();
    }

    /**
     * Helper method for playfair that replaces all capital Js in a String with capital Is.
     * @param str input string
     * @return string without js
     */
    private static String replaceJ(String str)
    {
        StringBuilder sb = new StringBuilder("");
        for(int i = 0; i < str.length(); i++)
        {
            if(str.charAt(i) == 'J')
            {
                sb.append('I');
            }
            else
            {
                sb.append(str.charAt(i));
            }
        }
        return sb.toString();
    }

    public static void main(String[] args)
    {
        System.out.println(playfair("Hide the gold in the tree stump", "playfair example"));
    }

}
