/*
 * Trivial program which requires no
 * additional imports
 */
public class HelloWorld {
	public static void main(String[] args) {
		int nr_sleeps = 5;
		for (;;) {
			System.out.println("Hello World");
			if (nr_sleeps == 0)
				System.exit(0);
			try {
				Thread.sleep(1000);
				nr_sleeps--;
			} catch(InterruptedException ex) {
				Thread.currentThread().interrupt();
			}
		}
	}
}
